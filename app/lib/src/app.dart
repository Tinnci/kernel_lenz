import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter_spinkit/flutter_spinkit.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';
import 'package:kernel_lens_app/src/common/theme/app_theme.dart';
import 'package:kernel_lens_app/src/common/widgets/glass_card.dart';
import 'package:kernel_lens_app/src/features/analysis/presentation/analysis_progress_card.dart';
import 'package:kernel_lens_app/src/features/analysis/presentation/analysis_controller.dart';
import 'package:kernel_lens_app/src/features/analysis/presentation/analysis_state.dart';
import 'package:kernel_lens_app/src/features/analysis/domain/failure_context.dart';
import 'package:kernel_lens_app/src/rust/api.dart';

class KernelLensApp extends ConsumerWidget {
  const KernelLensApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return MaterialApp(
      title: 'KernelLens',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.light,
      darkTheme: AppTheme.dark,
      themeMode: ThemeMode.system,
      home: const MainScreen(),
    );
  }
}

final navigationIndexProvider = StateProvider<int>((ref) => 0);

/// Responsive breakpoints following Material Design 3 guidelines
class Breakpoints {
  static const double mobile = 600; // Below: use BottomNavigation
  static const double tablet = 900; // Below: use compact NavigationRail
  static const double desktop = 1200; // Above: use extended NavigationRail
}

class MainScreen extends ConsumerWidget {
  const MainScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final selectedIndex = ref.watch(navigationIndexProvider);

    return LayoutBuilder(
      builder: (context, constraints) {
        final width = constraints.maxWidth;
        final isMobile = width < Breakpoints.mobile;
        final isCompact = width < Breakpoints.tablet;

        return Scaffold(
          // Mobile: Use bottom navigation
          bottomNavigationBar: isMobile
              ? NavigationBar(
                  selectedIndex: selectedIndex,
                  onDestinationSelected: (index) {
                    ref.read(navigationIndexProvider.notifier).state = index;
                  },
                  destinations: const [
                    NavigationDestination(
                      icon: Icon(Icons.analytics_outlined),
                      selectedIcon: Icon(Icons.analytics),
                      label: 'Analysis',
                    ),
                    NavigationDestination(
                      icon: Icon(Icons.history_outlined),
                      selectedIcon: Icon(Icons.history),
                      label: 'History',
                    ),
                    NavigationDestination(
                      icon: Icon(Icons.settings_outlined),
                      selectedIcon: Icon(Icons.settings),
                      label: 'Settings',
                    ),
                  ],
                )
              : null,
          body: Stack(
            children: [
              // Desktop/Tablet: Use NavigationRail
              if (!isMobile)
                Row(
                  children: [
                    NavigationRail(
                      selectedIndex: selectedIndex,
                      extended:
                          !isCompact, // Collapse rail on tablet-sized screens
                      minExtendedWidth: 200,
                      destinations: const [
                        NavigationRailDestination(
                          icon: Icon(Icons.analytics_outlined),
                          selectedIcon: Icon(Icons.analytics),
                          label: Text('Analysis'),
                        ),
                        NavigationRailDestination(
                          icon: Icon(Icons.history_outlined),
                          selectedIcon: Icon(Icons.history),
                          label: Text('History'),
                        ),
                        NavigationRailDestination(
                          icon: Icon(Icons.settings_outlined),
                          selectedIcon: Icon(Icons.settings),
                          label: Text('Settings'),
                        ),
                      ],
                      onDestinationSelected: (index) {
                        ref.read(navigationIndexProvider.notifier).state =
                            index;
                      },
                    ),
                    const VerticalDivider(thickness: 1, width: 1),
                    Expanded(
                      child: AnimatedSwitcher(
                        duration: 300.ms,
                        child: _buildBody(selectedIndex),
                      ),
                    ),
                  ],
                )
              else
                // Mobile: Full-width content
                AnimatedSwitcher(
                  duration: 300.ms,
                  child: _buildBody(selectedIndex),
                ),
              // 2026 Background Task Tray Implementation
              Positioned(
                left: isMobile ? 0 : 200, // Adjust for NavigationRail width
                right: 0,
                bottom: isMobile ? 56 : 0, // Above bottom nav on mobile
                child: _BackgroundTaskTray(),
              ),
            ],
          ),
        );
      },
    );
  }
}

class _BackgroundTaskTray extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(analysisControllerProvider);
    if (state.status == AnalysisStatus.idle ||
        state.status == AnalysisStatus.success) {
      return const SizedBox.shrink();
    }

    final isError = state.status == AnalysisStatus.failure;

    return Container(
      height: 36,
      padding: const EdgeInsets.symmetric(horizontal: 16),
      decoration: BoxDecoration(
        color: isError
            ? Theme.of(context).colorScheme.errorContainer.withAlpha(220)
            : Theme.of(context).colorScheme.primaryContainer.withAlpha(200),
        border: Border(
          top: BorderSide(
            color: isError
                ? Theme.of(context).colorScheme.error.withAlpha(50)
                : Theme.of(context).colorScheme.primary.withAlpha(50),
          ),
        ),
      ),
      child:
          Row(
            children: [
              if (isError)
                Icon(
                  Icons.warning_amber_rounded,
                  size: 14,
                  color: Theme.of(context).colorScheme.error,
                )
              else
                const SpinKitDoubleBounce(color: Colors.white, size: 12),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  isError
                      ? 'Analysis Failed: ${state.error?.message ?? 'Unknown'}'
                      : 'Running Deep Analysis: ${state.currentStep ?? 'Starting...'}',
                  style: TextStyle(
                    fontSize: 11,
                    fontWeight: FontWeight.bold,
                    fontFamily: 'monospace',
                    color: isError
                        ? Theme.of(context).colorScheme.error
                        : Theme.of(context).colorScheme.onPrimaryContainer,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              if (!isError) ...[
                const SizedBox(width: 12),
                SizedBox(
                  width: 100,
                  child: LinearProgressIndicator(
                    value: state.progress,
                    minHeight: 2,
                    backgroundColor: Colors.white.withAlpha(50),
                    valueColor: AlwaysStoppedAnimation<Color>(
                      Theme.of(context).colorScheme.primary,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Text(
                  '${((state.progress ?? 0) * 100).toInt()}%',
                  style: const TextStyle(
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ],
            ],
          ).animate().slideY(
            begin: 1.0,
            end: 0,
            duration: 400.ms,
            curve: Curves.easeOutCubic,
          ),
    );
  }
}

Widget _buildBody(int index) {
  switch (index) {
    case 0:
      return const AnalysisDashboard();
    case 1:
      return const Center(child: Text('History (Coming Soon)'));
    case 2:
      return const Center(child: Text('Settings (Coming Soon)'));
    default:
      return const AnalysisDashboard();
  }
}

void showSymbolsSheet(BuildContext context, WidgetRef ref) {
  showModalBottomSheet(
    context: context,
    isScrollControlled: true,
    backgroundColor: Colors.transparent,
    builder: (context) => const SymbolListSheet(),
  );
}

void showHexViewerSheet(
  BuildContext context,
  WidgetRef ref, {
  int? initialOffset,
}) {
  showModalBottomSheet(
    context: context,
    isScrollControlled: true,
    backgroundColor: Colors.transparent,
    builder: (context) => HexViewerSheet(initialOffset: initialOffset),
  );
}

class AnalysisDashboard extends ConsumerWidget {
  const AnalysisDashboard({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(analysisControllerProvider);

    return Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Theme.of(context).colorScheme.primaryContainer.withAlpha(50),
            Theme.of(context).colorScheme.surface,
          ],
        ),
      ),
      padding: const EdgeInsets.all(32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                'Kernel Analysis',
                style: Theme.of(context).textTheme.headlineLarge?.copyWith(
                  fontWeight: FontWeight.bold,
                  letterSpacing: -1,
                ),
              ),
              const Spacer(),
              const GlassCard(
                borderRadius: 30,
                child: Padding(
                  padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  child: Row(
                    children: [
                      Icon(Icons.memory, size: 16),
                      SizedBox(width: 8),
                      Text('v0.2.0-core'),
                    ],
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            'Securely recover symbols and reconstruct ELF files from binary images.',
            style: Theme.of(context).textTheme.bodyLarge?.copyWith(
              color: Theme.of(
                context,
              ).colorScheme.onSurface.withValues(alpha: 0.7),
            ),
          ),
          const SizedBox(height: 48),
          Expanded(
            child: SingleChildScrollView(
              child: Wrap(
                spacing: 24,
                runSpacing: 24,
                children: [
                  ConstrainedBox(
                    constraints: const BoxConstraints(
                      minWidth: 400,
                      maxWidth: 450,
                    ),
                    child: _buildActionCard(
                      context,
                      title: 'New Analysis',
                      subtitle: state.status == AnalysisStatus.loading
                          ? 'Processing...'
                          : 'Select boot.img or raw kernel',
                      icon: state.status == AnalysisStatus.loading
                          ? Icons.sync
                          : Icons.upload_file_rounded,
                      onTap: state.status == AnalysisStatus.loading
                          ? null
                          : () async {
                              final result = await FilePicker.platform
                                  .pickFiles();
                              if (result != null &&
                                  result.files.single.path != null) {
                                await ref
                                    .read(analysisControllerProvider.notifier)
                                    .analyze(result.files.single.path!);
                              }
                            },
                    ),
                  ),
                  if (state.status == AnalysisStatus.loading ||
                      state.status == AnalysisStatus.success)
                    ConstrainedBox(
                      constraints: const BoxConstraints(
                        minWidth: 400,
                        maxWidth: 450,
                      ),
                      child: AnalysisProgressCard(
                        step: state.currentStep ?? 'Analyzing...',
                        progress: state.progress ?? 0.0,
                        isCompleted: state.status == AnalysisStatus.success,
                      ),
                    ),
                  if (state.status == AnalysisStatus.failure)
                    ConstrainedBox(
                      constraints: const BoxConstraints(
                        minWidth: 400,
                        maxWidth: 450,
                      ),
                      child: _buildErrorCard(context, state.error!),
                    ),
                  if (state.summary != null) ...[
                    ConstrainedBox(
                      constraints: const BoxConstraints(
                        minWidth: 400,
                        maxWidth: 450,
                      ),
                      child: _buildResultCard(
                        context,
                        'Symbols Found',
                        '${state.summary?.symbolCount ?? 0}',
                        Icons.tag,
                        onTap: () => showSymbolsSheet(context, ref),
                      ),
                    ),
                    ConstrainedBox(
                      constraints: const BoxConstraints(
                        minWidth: 400,
                        maxWidth: 450,
                      ),
                      child: _buildResultCard(
                        context,
                        'Arch',
                        '${state.summary?.arch}',
                        Icons.settings_applications,
                      ),
                    ),
                    ConstrainedBox(
                      constraints: const BoxConstraints(
                        minWidth: 400,
                        maxWidth: 450,
                      ),
                      child: _buildResultCard(
                        context,
                        'ELF Dump',
                        'Hex Viewer',
                        Icons.settings_ethernet,
                        onTap: () => showHexViewerSheet(context, ref),
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildErrorCard(BuildContext context, FailureContext error) {
    return GlassCard(
      opacity: 0.1,
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(error.icon, color: error.color, size: 32),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        error.message,
                        style: Theme.of(context).textTheme.titleMedium
                            ?.copyWith(
                              color: error.color,
                              fontWeight: FontWeight.bold,
                            ),
                      ),
                      Text(
                        'Error Code: ${error.code}',
                        style: Theme.of(context).textTheme.labelSmall?.copyWith(
                          color: error.color.withAlpha(150),
                          fontFamily: 'monospace',
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: error.color.withAlpha(20),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: error.color.withAlpha(50)),
              ),
              child: Row(
                children: [
                  Icon(Icons.lightbulb_outline, size: 16, color: error.color),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      error.suggestion,
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        color: Theme.of(context).colorScheme.onSurface,
                        height: 1.5,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildResultCard(
    BuildContext context,
    String label,
    String value,
    IconData icon, {
    VoidCallback? onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: GlassCard(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Row(
            children: [
              Icon(icon, color: Theme.of(context).colorScheme.primary),
              const SizedBox(width: 16),
              Expanded(
                child: AnimatedSize(
                  duration: 300.ms,
                  curve: Curves.easeInOut,
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        label,
                        style: Theme.of(context).textTheme.labelMedium
                            ?.copyWith(
                              color: Theme.of(
                                context,
                              ).colorScheme.onSurface.withAlpha(150),
                            ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        value,
                        style: Theme.of(context).textTheme.headlineSmall
                            ?.copyWith(
                              fontWeight: FontWeight.w900,
                              fontFamily: 'monospace',
                            ),
                        softWrap: true,
                        overflow: TextOverflow.visible,
                      ),
                    ],
                  ),
                ),
              ),
              if (onTap != null)
                const Icon(
                  Icons.arrow_forward_ios,
                  size: 16,
                  color: Colors.grey,
                ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildActionCard(
    BuildContext context, {
    required String title,
    required String subtitle,
    required IconData icon,
    required VoidCallback? onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(16),
      child: GlassCard(
        opacity: 0.2,
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Row(
            children: [
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.primary.withAlpha(30),
                  borderRadius: BorderRadius.circular(12),
                ),
                child:
                    Icon(
                          icon,
                          size: 32,
                          color: Theme.of(context).colorScheme.primary,
                        )
                        .animate(
                          target: onTap == null ? 1 : 0,
                          onPlay: (controller) => controller.repeat(),
                        )
                        .rotate(duration: 2.seconds),
              ),
              const SizedBox(width: 20),
              Expanded(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: const TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    Text(
                      subtitle,
                      style: TextStyle(
                        color: Theme.of(
                          context,
                        ).colorScheme.onSurface.withAlpha(150),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class SymbolListSheet extends ConsumerStatefulWidget {
  const SymbolListSheet({super.key});

  @override
  ConsumerState<SymbolListSheet> createState() => _SymbolListSheetState();
}

class _SymbolListSheetState extends ConsumerState<SymbolListSheet> {
  final _searchController = TextEditingController();
  Timer? _debounce;

  @override
  void dispose() {
    _searchController.dispose();
    _debounce?.cancel();
    super.dispose();
  }

  void _onSearchChanged(String query) {
    if (_debounce?.isActive ?? false) _debounce?.cancel();
    _debounce = Timer(const Duration(milliseconds: 500), () {
      ref.read(analysisControllerProvider.notifier).updateFilter(query);
    });
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(analysisControllerProvider);
    final symbols = state.visibleSymbols ?? [];

    return DraggableScrollableSheet(
      initialChildSize: 0.9,
      maxChildSize: 0.95,
      minChildSize: 0.5,
      builder: (_, scrollController) => NotificationListener<ScrollNotification>(
        onNotification: (ScrollNotification scrollInfo) {
          if (scrollInfo.metrics.pixels >=
              scrollInfo.metrics.maxScrollExtent - 200) {
            ref.read(analysisControllerProvider.notifier).loadMore();
          }
          return true;
        },
        child: GlassCard(
          borderRadius: 24,
          child: Column(
            children: [
              const SizedBox(height: 12),
              Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.onSurface.withAlpha(50),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
              Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Text(
                          'Recovered Symbols (${state.summary?.symbolCount ?? 0})',
                          style: Theme.of(context).textTheme.headlineSmall
                              ?.copyWith(fontWeight: FontWeight.bold),
                        ),
                        const Spacer(),
                        IconButton(
                          icon: const Icon(Icons.close),
                          onPressed: () => Navigator.pop(context),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),
                    TextField(
                      controller: _searchController,
                      onChanged: _onSearchChanged,
                      decoration: InputDecoration(
                        hintText: 'Search symbols (e.g. sys_call_table)...',
                        prefixIcon: const Icon(Icons.search),
                        suffixIcon: state.status == AnalysisStatus.loading
                            ? const SizedBox(
                                width: 20,
                                height: 20,
                                child: Padding(
                                  padding: EdgeInsets.all(12),
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2,
                                  ),
                                ),
                              )
                            : null,
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(16),
                          borderSide: BorderSide.none,
                        ),
                        filled: true,
                        fillColor: Theme.of(
                          context,
                        ).colorScheme.surfaceContainerHighest.withAlpha(100),
                      ),
                    ),
                    const SizedBox(height: 12),
                    SingleChildScrollView(
                      scrollDirection: Axis.horizontal,
                      child: Row(
                        children: [
                          _SortChip(
                            label: 'Address',
                            column: SortColumn.address,
                            activeColumn: state.currentSort,
                            ascending: state.ascending,
                            onTap: () => ref
                                .read(analysisControllerProvider.notifier)
                                .updateSort(SortColumn.address),
                          ),
                          const SizedBox(width: 8),
                          _SortChip(
                            label: 'Name',
                            column: SortColumn.name,
                            activeColumn: state.currentSort,
                            ascending: state.ascending,
                            onTap: () => ref
                                .read(analysisControllerProvider.notifier)
                                .updateSort(SortColumn.name),
                          ),
                          const SizedBox(width: 8),
                          _SortChip(
                            label: 'Type',
                            column: SortColumn.type,
                            activeColumn: state.currentSort,
                            ascending: state.ascending,
                            onTap: () => ref
                                .read(analysisControllerProvider.notifier)
                                .updateSort(SortColumn.type),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
              Expanded(
                child: ListView.builder(
                  controller: scrollController,
                  padding: const EdgeInsets.symmetric(horizontal: 24),
                  itemCount: symbols.length + (state.isLoadingMore ? 1 : 0),
                  itemBuilder: (context, index) {
                    if (index == symbols.length) {
                      return const Padding(
                        padding: EdgeInsets.symmetric(vertical: 24),
                        child: Center(
                          child: CircularProgressIndicator(strokeWidth: 2),
                        ),
                      );
                    }

                    final sym = symbols[index];
                    return ListTile(
                      leading: CircleAvatar(
                        backgroundColor: Theme.of(
                          context,
                        ).colorScheme.primaryContainer,
                        child: Text(
                          sym.stype,
                          style: TextStyle(
                            color: Theme.of(context).colorScheme.primary,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                      title: Text(
                        sym.name,
                        style: const TextStyle(fontFamily: 'monospace'),
                      ),
                      subtitle: Text(
                        '0x${sym.addr.toRadixString(16).padLeft(16, '0')}',
                        style: TextStyle(
                          color: Theme.of(
                            context,
                          ).colorScheme.onSurface.withAlpha(120),
                        ),
                      ),
                      trailing: IconButton(
                        icon: const Icon(Icons.data_object, size: 20),
                        tooltip: 'View in Hex',
                        onPressed: () {
                          Navigator.pop(context);
                          showHexViewerSheet(
                            context,
                            ref,
                            initialOffset: sym.addr.toInt(),
                          );
                        },
                      ),
                    );
                  },
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _SortChip extends StatelessWidget {
  final String label;
  final SortColumn column;
  final SortColumn activeColumn;
  final bool ascending;
  final VoidCallback onTap;

  const _SortChip({
    required this.label,
    required this.column,
    required this.activeColumn,
    required this.ascending,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final bool isActive = column == activeColumn;

    return FilterChip(
      label: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(label),
          if (isActive) ...[
            const SizedBox(width: 4),
            Icon(
              ascending ? Icons.arrow_upward : Icons.arrow_downward,
              size: 14,
            ),
          ],
        ],
      ),
      selected: isActive,
      onSelected: (_) => onTap(),
      backgroundColor: Colors.transparent,
      selectedColor: Theme.of(context).colorScheme.primary.withAlpha(50),
      checkmarkColor: Theme.of(context).colorScheme.primary,
      showCheckmark: false,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(
          color: isActive
              ? Theme.of(context).colorScheme.primary
              : Theme.of(context).colorScheme.outline.withAlpha(50),
        ),
      ),
    );
  }
}

class HexViewerSheet extends ConsumerStatefulWidget {
  final int? initialOffset;
  const HexViewerSheet({super.key, this.initialOffset});

  @override
  ConsumerState<HexViewerSheet> createState() => _HexViewerSheetState();
}

class _HexViewerSheetState extends ConsumerState<HexViewerSheet> {
  final int _linesPerBlock = 128;
  late final ScrollController _scrollController;
  final _addressController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _scrollController = ScrollController();
    if (widget.initialOffset != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        _jumpToOffset(widget.initialOffset!);
      });
    }
  }

  @override
  void dispose() {
    _scrollController.dispose();
    _addressController.dispose();
    super.dispose();
  }

  void _jumpToOffset(int offset) {
    final lineIndex = offset ~/ 16;
    final scrollPos = lineIndex * 28.0; // 28 is itemExtent
    if (_scrollController.hasClients) {
      _scrollController.animateTo(
        scrollPos,
        duration: const Duration(milliseconds: 500),
        curve: Curves.easeOutCubic,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(analysisControllerProvider);
    final kernelSize = state.summary?.kernelSize.toInt() ?? 0;
    final totalLines = (kernelSize / 16).ceil();

    return DraggableScrollableSheet(
      initialChildSize: 0.9,
      maxChildSize: 0.95,
      minChildSize: 0.5,
      builder: (_, scrollController) => GlassCard(
        borderRadius: 24,
        child: Column(
          children: [
            const SizedBox(height: 12),
            Container(
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.onSurface.withAlpha(50),
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            Padding(
              padding: const EdgeInsets.all(24),
              child: Row(
                children: [
                  Text(
                    'Hex Explorer',
                    style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                  const SizedBox(width: 24),
                  Expanded(
                    child: SizedBox(
                      height: 40,
                      child: TextField(
                        controller: _addressController,
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 13,
                        ),
                        decoration: InputDecoration(
                          hintText: 'Jump to address (hex)...',
                          prefixIcon: const Icon(Icons.near_me, size: 16),
                          filled: true,
                          fillColor: Theme.of(
                            context,
                          ).colorScheme.surfaceContainerHighest.withAlpha(80),
                          contentPadding: const EdgeInsets.symmetric(
                            horizontal: 16,
                          ),
                          border: OutlineInputBorder(
                            borderRadius: BorderRadius.circular(20),
                            borderSide: BorderSide.none,
                          ),
                        ),
                        onSubmitted: (value) {
                          final cleanValue = value.replaceFirst('0x', '');
                          final offset = int.tryParse(cleanValue, radix: 16);
                          if (offset != null) {
                            _jumpToOffset(offset);
                          }
                        },
                      ),
                    ),
                  ),
                  const SizedBox(width: 24),
                  Text(
                    '${(kernelSize / 1024 / 1024).toStringAsFixed(2)} MB total',
                    style: TextStyle(
                      color: Theme.of(
                        context,
                      ).colorScheme.onSurface.withAlpha(120),
                    ),
                  ),
                  const SizedBox(width: 12),
                  IconButton(
                    icon: const Icon(Icons.close),
                    onPressed: () => Navigator.pop(context),
                  ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 8),
              child: DefaultTextStyle(
                style: TextStyle(
                  fontFamily: 'monospace',
                  fontWeight: FontWeight.bold,
                  color: Theme.of(context).colorScheme.primary.withAlpha(180),
                ),
                child: const Row(
                  children: [
                    SizedBox(width: 85, child: Text('OFFSET')),
                    SizedBox(width: 12),
                    Expanded(child: Text('HEX BYTES')),
                    SizedBox(width: 8),
                    SizedBox(width: 130, child: Text('ASCII')),
                  ],
                ),
              ),
            ),
            const Divider(height: 1),
            Expanded(
              child: ListView.builder(
                controller: _scrollController,
                itemExtent: 28,
                itemCount: totalLines,
                padding: const EdgeInsets.symmetric(vertical: 8),
                itemBuilder: (context, index) {
                  final chunk = state.hexCache[index];

                  if (chunk == null) {
                    final startLine =
                        (index ~/ _linesPerBlock) * _linesPerBlock;
                    ref
                        .read(analysisControllerProvider.notifier)
                        .loadHexRange(startLine, _linesPerBlock);

                    return const _HexLineLoading();
                  }

                  return _HexLine(index: index, chunk: chunk);
                },
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _HexLine extends StatelessWidget {
  final int index;
  final HexChunk chunk;

  const _HexLine({required this.index, required this.chunk});

  @override
  Widget build(BuildContext context) {
    final offset = index * 16;
    final bytes = chunk.content;

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 24),
      child: Row(
        children: [
          SizedBox(
            width: 85,
            child: Text(
              offset.toRadixString(16).padLeft(8, '0').toUpperCase(),
              style: TextStyle(
                fontFamily: 'monospace',
                color: Theme.of(context).colorScheme.onSurface.withAlpha(100),
                fontSize: 13,
              ),
            ),
          ),
          const SizedBox(width: 12),
          // Use Expanded with a clipped layout to prevent overflow
          Expanded(
            child: LayoutBuilder(
              builder: (context, constraints) {
                // Calculate available width per byte
                // 16 bytes + group spacing (3 groups * 6px) = 16 * byteWidth + 18
                final byteWidth = (constraints.maxWidth - 18) / 16;

                return Row(
                  mainAxisSize: MainAxisSize.min,
                  children: List.generate(16, (i) {
                    if (i >= bytes.length) {
                      return SizedBox(width: byteWidth);
                    }
                    final b = bytes[i];
                    final hex = b
                        .toRadixString(16)
                        .padLeft(2, '0')
                        .toUpperCase();
                    final isGroupEnd = (i + 1) % 4 == 0 && i < 15;

                    return SizedBox(
                      width: byteWidth + (isGroupEnd ? 6 : 0),
                      child: Text(
                        hex,
                        style: TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 12,
                          color: b == 0
                              ? Theme.of(
                                  context,
                                ).colorScheme.onSurface.withAlpha(40)
                              : Theme.of(context).colorScheme.onSurface,
                        ),
                      ),
                    );
                  }),
                );
              },
            ),
          ),
          const SizedBox(width: 8),
          // ASCII column - use Text with ellipsis for overflow protection
          SizedBox(
            width: 130,
            child: Text(
              String.fromCharCodes(
                bytes.map((b) => (b >= 32 && b <= 126) ? b : 46),
              ),
              style: TextStyle(
                fontFamily: 'monospace',
                fontSize: 12,
                color: Theme.of(context).colorScheme.primary.withAlpha(150),
              ),
              overflow: TextOverflow.clip,
            ),
          ),
        ],
      ),
    );
  }
}

class _HexLineLoading extends StatelessWidget {
  const _HexLineLoading();

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 24),
      child: Row(
        children: [
          Container(
            width: 85,
            height: 12,
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.onSurface.withAlpha(20),
              borderRadius: BorderRadius.circular(4),
            ),
          ),
          const SizedBox(width: 20),
          Expanded(
            child: Container(
              height: 12,
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.onSurface.withAlpha(10),
                borderRadius: BorderRadius.circular(4),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
