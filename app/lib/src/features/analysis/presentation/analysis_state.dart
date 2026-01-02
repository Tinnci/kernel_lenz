import 'package:kernel_lens_app/src/rust/api.dart';

enum AnalysisStatus { idle, loading, success, failure }

class AnalysisState {
  final AnalysisStatus status;
  final String? currentStep;
  final double? progress;
  final AnalysisSession? session;
  final AnalysisSummary? summary;
  final List<FrbKernelSymbol>? visibleSymbols;
  final String? error;

  const AnalysisState({
    this.status = AnalysisStatus.idle,
    this.currentStep,
    this.progress,
    this.session,
    this.summary,
    this.visibleSymbols,
    this.error,
  });

  AnalysisState copyWith({
    AnalysisStatus? status,
    String? currentStep,
    double? progress,
    AnalysisSession? session,
    AnalysisSummary? summary,
    List<FrbKernelSymbol>? visibleSymbols,
    String? error,
  }) {
    return AnalysisState(
      status: status ?? this.status,
      currentStep: currentStep ?? this.currentStep,
      progress: progress ?? this.progress,
      session: session ?? this.session,
      summary: summary ?? this.summary,
      visibleSymbols: visibleSymbols ?? this.visibleSymbols,
      error: error ?? this.error,
    );
  }
}
