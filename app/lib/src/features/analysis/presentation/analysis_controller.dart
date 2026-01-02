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
      // Step 1: Detect compression
      state = state.copyWith(currentStep: 'Detecting format...', progress: 0.2);
      await detectCompression(path: path);

      // Step 2: Full analysis

      // Step 2: Create analysis session
      state = state.copyWith(
        currentStep: 'Processing kernel...',
        progress: 0.5,
      );

      final session = await AnalysisSession.newInstance(inputPath: path);

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
        state.status == AnalysisStatus.loading) {
      return;
    }

    final nextPage = state.currentPage + 1;
    try {
      final newSymbols = await session.querySymbols(
        filter: "",
        sortBy: SortColumn.address,
        ascending: true,
        page: BigInt.from(nextPage),
        pageSize: BigInt.from(100),
      );

      if (newSymbols.isEmpty) {
        state = state.copyWith(hasMore: false);
      } else {
        state = state.copyWith(
          visibleSymbols: [...?state.visibleSymbols, ...newSymbols],
          currentPage: nextPage,
          hasMore: newSymbols.length >= 100,
        );
      }
    } catch (e) {
      // Quietly fail or handle error
      print("Error loading more symbols: $e");
    }
  }

  void reset() {
    state = const AnalysisState();
  }
}
