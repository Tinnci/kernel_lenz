import 'dart:ui';
import 'package:flutter/material.dart';

class GlassCard extends StatelessWidget {
  final Widget child;
  final double blur;
  final double opacity;
  final double borderRadius;

  const GlassCard({
    super.key,
    required this.child,
    this.blur = 10,
    this.opacity = 0.1,
    this.borderRadius = 16,
  });

  @override
  Widget build(BuildContext context) {
    return ClipRRect(
      borderRadius: BorderRadius.circular(borderRadius),
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: blur, sigmaY: blur),
        child: Container(
          decoration: BoxDecoration(
            color: Theme.of(
              context,
            ).colorScheme.surface.withValues(alpha: opacity),
            borderRadius: BorderRadius.circular(borderRadius),
            border: Border.all(
              color: Theme.of(
                context,
              ).colorScheme.outline.withValues(alpha: 0.1),
              width: 1,
            ),
          ),
          child: child,
        ),
      ),
    );
  }
}
