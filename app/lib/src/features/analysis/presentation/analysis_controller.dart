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
      state = state.copyWith(
        currentStep: 'Processing kernel...',
        progress: 0.5,
      );
      final result = await analyzeKernel(inputPath: path);

      state = state.copyWith(
        status: AnalysisStatus.success,
        currentStep: 'Analysis complete',
        progress: 1.0,
        result: result,
      );
    } catch (e) {
      state = state.copyWith(
        status: AnalysisStatus.failure,
        error: e.toString(),
        progress: 0.0,
      );
    }
  }

  void reset() {
    state = const AnalysisState();
  }
}
