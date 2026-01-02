import 'package:kernel_lens_app/src/rust/api.dart';

enum AnalysisStatus { idle, loading, success, failure }

class AnalysisState {
  final AnalysisStatus status;
  final String? currentStep;
  final double? progress;
  final AnalysisResult? result;
  final String? error;

  const AnalysisState({
    this.status = AnalysisStatus.idle,
    this.currentStep,
    this.progress,
    this.result,
    this.error,
  });

  AnalysisState copyWith({
    AnalysisStatus? status,
    String? currentStep,
    double? progress,
    AnalysisResult? result,
    String? error,
  }) {
    return AnalysisState(
      status: status ?? this.status,
      currentStep: currentStep ?? this.currentStep,
      progress: progress ?? this.progress,
      result: result ?? this.result,
      error: error ?? this.error,
    );
  }
}
