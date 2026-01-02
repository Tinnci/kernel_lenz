import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:kernel_lens_app/src/common/widgets/glass_card.dart';

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
    return GlassCard(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    step,
                    style: const TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.w600,
                    ),
                  ).animate().fadeIn().moveX(begin: -10, end: 0),
                ),
                if (isCompleted)
                  const Icon(
                    Icons.check_circle,
                    color: Colors.green,
                  ).animate().scale(),
              ],
            ),
            const SizedBox(height: 16),
            ClipRRect(
              borderRadius: BorderRadius.circular(8),
              child: LinearProgressIndicator(
                value: progress,
                minHeight: 8,
                backgroundColor: Theme.of(
                  context,
                ).colorScheme.surfaceContainerHighest,
                valueColor: AlwaysStoppedAnimation<Color>(
                  Theme.of(context).colorScheme.primary,
                ),
              ),
            ).animate().shimmer(duration: 2.seconds),
            const SizedBox(height: 8),
            Text(
              '${(progress * 100).toInt()}%',
              style: Theme.of(context).textTheme.labelMedium,
            ),
          ],
        ),
      ),
    );
  }
}
