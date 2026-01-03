import 'dart:async';
import 'dart:io';
import 'package:kernel_lens_app/src/features/analysis/domain/failure_context.dart';
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
    AppLogger.i('Analysis Request: $path');

    // 1. Boundary Validation: Google FFI Practice
    if (!File(path).existsSync()) {
      AppLogger.e('Target file missing: $path');
      state = state.copyWith(
        status: AnalysisStatus.failure,
        error: const FailureContext(
          code: 'FILE_NOT_FOUND',
          message: 'Source File Missing',
          suggestion:
              'The selected image file no longer exists. Please re-select the file.',
          severity: FailureSeverity.critical,
        ),
      );
      return;
    }

    state = state.copyWith(
      status: AnalysisStatus.loading,
      currentStep: 'Initializing engine...',
      progress: 0.1,
      error: null,
    );

    try {
      AppLogger.d('Starting analysis stream...');
      final stream = startAnalysis(inputPath: path);
      final completer = Completer<void>();

      stream.listen(
        (update) async {
          AppLogger.d('Stream Update: ${update.step} (${(update.progress * 100).toStringAsFixed(1)}%)');
          
          if (update.session != null) {
            final session = update.session!;
            AppLogger.i('Session received, querying initial symbols...');
            
            try {
              final symbols = await session.querySymbols(
                filter: "",
                sortBy: SortColumn.address,
                ascending: true,
                page: BigInt.zero,
                pageSize: BigInt.from(100),
              );

              state = state.copyWith(
                status: AnalysisStatus.success,
                currentStep: 'Analysis Complete',
                progress: 1.0,
                session: session,
                summary: session.summary,
                visibleSymbols: symbols,
                currentPage: 0,
                hasMore: symbols.length >= 100,
              );
            } catch (e, stack) {
              AppLogger.e('Initial symbol query failed', e, stack);
              if (!completer.isCompleted) completer.completeError(e, stack);
            }
          } else {
            state = state.copyWith(
              currentStep: update.step,
              progress: update.progress,
              summary: update.summary ?? state.summary,
            );
          }
        },
        onError: (e, stack) {
          AppLogger.e('Stream onError caught', e, stack);
          if (!completer.isCompleted) completer.completeError(e, stack);
        },
        onDone: () {
          AppLogger.d('Stream onDone reached');
          if (!completer.isCompleted) completer.complete();
        },
        cancelOnError: true,
      );

      await completer.future;
      AppLogger.d('Analysis pipeline finished successfully.');
    } catch (e, stack) {
      AppLogger.e('Analysis Pipeline Failure', e, stack);
      state = state.copyWith(
        status: AnalysisStatus.failure,
        error: _mapError(e.toString()),
        progress: 0.0,
      );
    }
  }

  FailureContext _mapError(String error) {
    if (error.contains('Kallsyms not found')) {
      return const FailureContext(
        code: 'KALLSYMS_NOT_FOUND',
        message: 'Kernel Symbol Table Not Found',
        suggestion:
            'This image might be stripped or encrypted. Try providing a manual base address if you know the kalsyms offset.',
        severity: FailureSeverity.critical,
      );
    }

    if (error.contains('Permission denied')) {
      return const FailureContext(
        code: 'PERMISSION_DENIED',
        message: 'Access Denied',
        suggestion:
            'The application lacks permissions to read the source file. Try moving the image to a different directory or running as Administrator.',
        severity: FailureSeverity.operational,
      );
    }

    return FailureContext(
      code: 'UNKNOWN_FAILURE',
      message: 'Analysis Failed Unexpectedly',
      suggestion: 'Check the logs for more details or retry the analysis.',
      severity: FailureSeverity.technical,
      metadata: {'raw': error},
    );
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
