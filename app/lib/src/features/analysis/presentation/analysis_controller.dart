import 'dart:developer' as developer;
import 'package:kernel_lens_app/src/rust/api.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';
import 'package:kernel_lens_app/src/features/analysis/presentation/analysis_state.dart';

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
      final stream = startAnalysis(inputPath: path);

      await for (final update in stream) {
        if (update.session != null) {
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
        sortBy: SortColumn.address,
        ascending: true,
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
    } catch (e) {
      developer.log("Error loading more symbols", error: e);
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
        sortBy: SortColumn.address,
        ascending: true,
        page: BigInt.zero,
        pageSize: BigInt.from(100),
      );

      state = state.copyWith(
        status: AnalysisStatus.success,
        visibleSymbols: symbols,
        hasMore: symbols.length >= 100,
      );
    } catch (e) {
      developer.log("Error filtering symbols", error: e);
    }
  }

  void reset() {
    state = const AnalysisState();
  }
}
