import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter_spinkit/flutter_spinkit.dart';
import 'package:kernel_lens_app/src/common/widgets/glass_card.dart';

/// 2026 Modern Analysis Progress UI
/// Implements "perceived performance" patterns:
/// - Smooth progress animation
/// - Industrial micro-interactions
/// - Granular step reporting
class AnalysisProgressCard extends StatelessWidget {
  final String step;
  final double progress;
  final bool isCompleted;

  const AnalysisProgressCard({
    super.key,
    required this.step,
    required this.progress,
    this.isCompleted = false,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return GlassCard(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                // SpinKit for industrial/data processing feel
                if (!isCompleted)
                  SizedBox(
                    width: 24,
                    height: 24,
                    child: SpinKitDoubleBounce(
                      color: theme.colorScheme.primary,
                      size: 20.0,
                    ),
                  )
                else
                  Icon(
                    Icons.check_circle,
                    color: Colors.green.shade400,
                    size: 24,
                  ).animate().scale(
                    duration: 400.ms,
                    curve: Curves.easeOutBack,
                  ),

                const SizedBox(width: 16),

                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        isCompleted ? 'Analysis Complete' : 'Kernel Deep Scan',
                        style: theme.textTheme.titleSmall?.copyWith(
                          color: theme.colorScheme.onSurface.withAlpha(150),
                          letterSpacing: 1.2,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Flexible(
                        child:
                            Text(
                                  step,
                                  style: theme.textTheme.titleMedium?.copyWith(
                                    fontWeight: FontWeight.bold,
                                    fontFamily: 'monospace',
                                  ),
                                  maxLines: 2,
                                  overflow: TextOverflow.ellipsis,
                                )
                                .animate(key: ValueKey(step))
                                .fadeIn()
                                .slideX(begin: 0.1, end: 0),
                      ),
                    ],
                  ),
                ),

                Text(
                  '${(progress * 100).toStringAsFixed(0)}%',
                  style: theme.textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.w900,
                    fontFamily: 'monospace',
                    color: theme.colorScheme.primary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 24),

            // Progressive Loading Bar with Shimmer
            Stack(
              children: [
                ClipRRect(
                  borderRadius: BorderRadius.circular(12),
                  child: Container(
                    height: 10,
                    width: double.infinity,
                    color: theme.colorScheme.surfaceContainerHighest.withAlpha(
                      80,
                    ),
                  ),
                ),
                AnimatedContainer(
                      duration: 600.ms,
                      curve: Curves.easeOutCubic,
                      height: 10,
                      width:
                          (MediaQuery.of(context).size.width * 0.3) *
                          progress.clamp(0.01, 1.0),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(12),
                        gradient: LinearGradient(
                          colors: [
                            theme.colorScheme.primary,
                            theme.colorScheme.tertiary,
                          ],
                        ),
                        boxShadow: [
                          BoxShadow(
                            color: theme.colorScheme.primary.withAlpha(100),
                            blurRadius: 8,
                            offset: const Offset(0, 2),
                          ),
                        ],
                      ),
                    )
                    .animate(onPlay: (c) => c.repeat())
                    .shimmer(
                      duration: 3.seconds,
                      color: Colors.white.withAlpha(50),
                    ),
              ],
            ),

            if (!isCompleted) ...[
              const SizedBox(height: 16),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'Sub-process: FFI/Rust Thread 0',
                    style: theme.textTheme.labelSmall?.copyWith(
                      color: theme.colorScheme.onSurface.withAlpha(100),
                    ),
                  ),
                  Text(
                    'Scanning offset...',
                    style: theme.textTheme.labelSmall?.copyWith(
                      color: theme.colorScheme.secondary.withAlpha(150),
                      fontStyle: FontStyle.italic,
                    ),
                  ),
                ],
              ),
            ],
          ],
        ),
      ),
    );
  }
}
