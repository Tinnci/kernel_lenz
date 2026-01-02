import 'package:kernel_lens_app/src/rust/api.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';
import 'package:kernel_lens_app/src/features/analysis/presentation/analysis_state.dart';
import 'package:kernel_lens_app/src/common/utils/logger.dart';

part 'analysis_controller.g.dart';

@riverpod
class AnalysisController extends _$AnalysisController {
  @override
  AnalysisState build() => const AnalysisState();

  Future<void> analyze(String path) async {
    state = state.copyWith(
      status: AnalysisStatus.loading,
      currentStep: 'Initializing...',
      progress: 0.1,
      error: null,
    );

    try {
      AppLogger.i('Starting analysis for: $path');
      final stream = startAnalysis(inputPath: path);

      await for (final update in stream) {
        AppLogger.d(
          'FFI Progress: ${update.step} (${(update.progress * 100).toStringAsFixed(1)}%)',
        );

        if (update.session != null) {
          AppLogger.i('Analysis successful, received session object.');
          final session = update.session!;
          // Initial query (first 100 items)
          final symbols = await session.querySymbols(
            filter: "",
            sortBy: SortColumn.address,
            ascending: true,
            page: BigInt.zero,
            pageSize: BigInt.from(100),
          );

          state = state.copyWith(
            status: AnalysisStatus.success,
            currentStep: 'Analysis complete',
            progress: 1.0,
            session: session,
            summary: session.summary,
            visibleSymbols: symbols,
            currentPage: 0,
            hasMore: symbols.length >= 100,
          );
        } else {
          state = state.copyWith(
            currentStep: update.step,
            progress: update.progress,
          );
        }
      }
    } catch (e) {
      state = state.copyWith(
        status: AnalysisStatus.failure,
        error: e.toString(),
        progress: 0.0,
      );
    }
  }

  Future<void> loadMore() async {
    final session = state.session;
    if (session == null ||
        !state.hasMore ||
        state.isLoadingMore ||
        state.status == AnalysisStatus.loading) {
      return;
    }

    state = state.copyWith(isLoadingMore: true);

    final nextPage = state.currentPage + 1;
    try {
      final newSymbols = await session.querySymbols(
        filter: state.currentFilter,
        sortBy: state.currentSort,
        ascending: state.ascending,
        page: BigInt.from(nextPage),
        pageSize: BigInt.from(100),
      );

      if (newSymbols.isEmpty) {
        state = state.copyWith(hasMore: false, isLoadingMore: false);
      } else {
        state = state.copyWith(
          visibleSymbols: [...?state.visibleSymbols, ...newSymbols],
          currentPage: nextPage,
          hasMore: newSymbols.length >= 100,
          isLoadingMore: false,
        );
      }
    } catch (e, stack) {
      AppLogger.e('Error loading more symbols', e, stack);
      state = state.copyWith(isLoadingMore: false);
    }
  }

  Future<void> updateFilter(String filter) async {
    final session = state.session;
    if (session == null) return;

    state = state.copyWith(
      status: AnalysisStatus.loading,
      currentPage: 0,
      currentFilter: filter,
    );

    try {
      final symbols = await session.querySymbols(
        filter: filter,
        sortBy: state.currentSort,
        ascending: state.ascending,
        page: BigInt.zero,
        pageSize: BigInt.from(100),
      );

      state = state.copyWith(
        status: AnalysisStatus.success,
        visibleSymbols: symbols,
        hasMore: symbols.length >= 100,
      );
    } catch (e, stack) {
      AppLogger.e("Error filtering symbols", e, stack);
    }
  }

  Future<void> updateSort(SortColumn column) async {
    final session = state.session;
    if (session == null) return;

    // If same column, toggle ascending. If new column, default to ascending.
    final bool newAscending = (state.currentSort == column)
        ? !state.ascending
        : true;

    state = state.copyWith(
      status: AnalysisStatus.loading,
      currentPage: 0,
      currentSort: column,
      ascending: newAscending,
    );

    try {
      final symbols = await session.querySymbols(
        filter: state.currentFilter,
        sortBy: column,
        ascending: newAscending,
        page: BigInt.zero,
        pageSize: BigInt.from(100),
      );

      state = state.copyWith(
        status: AnalysisStatus.success,
        visibleSymbols: symbols,
        hasMore: symbols.length >= 100,
      );
    } catch (e, stack) {
      AppLogger.e("Error updating sort", e, stack);
    }
  }

  Future<void> jumpToAddress(int address) async {
    final session = state.session;
    if (session == null) return;

    // Convert address to file offset (assuming 1:1 for now if it's a raw kernel,
    // or offset from base if it's an ELF).
    // For simplicity in this UI iteration, we treat it as an absolute offset.
    final int offset = address;
    final int lineIndex = offset ~/ 16;

    // Predispatch the load for this block
    final int startLine = (lineIndex ~/ 128) * 128;
    await loadHexRange(startLine, 128);
  }

  Future<void> loadHexRange(int startLine, int count) async {
    final session = state.session;
    if (session == null) return;

    // Check if we already have the data to avoid double fetch
    if (state.hexCache.containsKey(startLine)) return;

    try {
      final offset = BigInt.from(startLine * 16);
      final length = BigInt.from(count * 16);

      final chunk = await session.getHexChunk(offset: offset, length: length);

      // Distribute bytes back into 16-byte lines in the cache
      final Map<int, HexChunk> newCache = Map.from(state.hexCache);
      final bytes = chunk.content;

      for (int i = 0; i < count; i++) {
        final lineOffset = i * 16;
        if (lineOffset + 16 > bytes.length) break;

        final lineBytes = bytes.sublist(lineOffset, lineOffset + 16);
        final currentLineIndex = startLine + i;

        newCache[currentLineIndex] = HexChunk(
          content: lineBytes,
          offset: BigInt.from(currentLineIndex * 16),
          totalSize: chunk.totalSize,
        );
      }

      state = state.copyWith(hexCache: newCache);
    } catch (e, stack) {
      AppLogger.e("Error loading hex range", e, stack);
    }
  }

  void clearHexCache() {
    state = state.copyWith(hexCache: {});
  }

  void reset() {
    state = const AnalysisState();
  }
}
