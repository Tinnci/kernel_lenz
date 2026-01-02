import 'package:kernel_lens_app/src/rust/api.dart';

enum AnalysisStatus { idle, loading, success, failure }

class AnalysisState {
  final AnalysisStatus status;
  final String? currentStep;
  final double? progress;
  final AnalysisSession? session;
  final AnalysisSummary? summary;
  final List<FrbKernelSymbol>? visibleSymbols;
  final int currentPage;
  final bool hasMore;
  final bool isLoadingMore;
  final String currentFilter;
  final SortColumn currentSort;
  final bool ascending;
  final String? error;

  const AnalysisState({
    this.status = AnalysisStatus.idle,
    this.currentStep,
    this.progress,
    this.session,
    this.summary,
    this.visibleSymbols,
    this.currentPage = 0,
    this.hasMore = true,
    this.isLoadingMore = false,
    this.currentFilter = '',
    this.currentSort = SortColumn.address,
    this.ascending = true,
    this.error,
  });

  AnalysisState copyWith({
    AnalysisStatus? status,
    String? currentStep,
    double? progress,
    AnalysisSession? session,
    AnalysisSummary? summary,
    List<FrbKernelSymbol>? visibleSymbols,
    int? currentPage,
    bool? hasMore,
    bool? isLoadingMore,
    String? currentFilter,
    SortColumn? currentSort,
    bool? ascending,
    String? error,
  }) {
    return AnalysisState(
      status: status ?? this.status,
      currentStep: currentStep ?? this.currentStep,
      progress: progress ?? this.progress,
      session: session ?? this.session,
      summary: summary ?? this.summary,
      visibleSymbols: visibleSymbols ?? this.visibleSymbols,
      currentPage: currentPage ?? this.currentPage,
      hasMore: hasMore ?? this.hasMore,
      isLoadingMore: isLoadingMore ?? this.isLoadingMore,
      currentFilter: currentFilter ?? this.currentFilter,
      currentSort: currentSort ?? this.currentSort,
      ascending: ascending ?? this.ascending,
      error: error ?? this.error,
    );
  }
}
