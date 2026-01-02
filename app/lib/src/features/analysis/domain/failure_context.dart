import 'package:flutter/material.dart';

enum FailureSeverity { technical, operational, critical }

/// 2026 Standard Failure Context for FFI/Rust errors.
/// Provides not just the "what", but the "how to fix".
class FailureContext {
  final String code;
  final String message;
  final String suggestion;
  final FailureSeverity severity;
  final Map<String, dynamic>? metadata;
  final List<String> breadcrumbs;

  const FailureContext({
    required this.code,
    required this.message,
    required this.suggestion,
    this.severity = FailureSeverity.technical,
    this.metadata,
    this.breadcrumbs = const [],
  });

  IconData get icon {
    switch (severity) {
      case FailureSeverity.technical:
        return Icons.build_circle_outlined;
      case FailureSeverity.operational:
        return Icons.info_outline;
      case FailureSeverity.critical:
        return Icons.report_problem_outlined;
    }
  }

  Color get color {
    switch (severity) {
      case FailureSeverity.technical:
        return Colors.orange.shade400;
      case FailureSeverity.operational:
        return Colors.blue.shade400;
      case FailureSeverity.critical:
        return Colors.red.shade400;
    }
  }
}
