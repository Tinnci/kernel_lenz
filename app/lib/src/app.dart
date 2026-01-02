import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';
import 'package:kernel_lens_app/src/common/theme/app_theme.dart';
import 'package:kernel_lens_app/src/common/widgets/glass_card.dart';
import 'package:kernel_lens_app/src/features/analysis/presentation/analysis_progress_card.dart';
import 'package:kernel_lens_app/src/features/analysis/presentation/analysis_controller.dart';
import 'package:kernel_lens_app/src/features/analysis/presentation/analysis_state.dart';

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

class MainScreen extends ConsumerWidget {
  const MainScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final selectedIndex = ref.watch(navigationIndexProvider);

    return Scaffold(
      body: Row(
        children: [
          NavigationRail(
            selectedIndex: selectedIndex,
            extended: true,
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
              ref.read(navigationIndexProvider.notifier).state = index;
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
      ),
    );
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
                  SizedBox(
                    width: 400,
                    height: 160,
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
                    SizedBox(
                      width: 400,
                      height: 160,
                      child: AnalysisProgressCard(
                        step: state.currentStep ?? 'Analyzing...',
                        progress: state.progress ?? 0.0,
                        isCompleted: state.status == AnalysisStatus.success,
                      ),
                    ),
                  if (state.status == AnalysisStatus.failure)
                    SizedBox(
                      width: 400,
                      height: 160,
                      child: _buildErrorCard(
                        context,
                        state.error ?? 'Unknown error',
                      ),
                    ),
                  if (state.status == AnalysisStatus.success) ...[
                    SizedBox(
                      width: 400,
                      height: 160,
                      child: _buildResultCard(
                        context,
                        'Symbols Found',
                        '${state.summary?.symbolCount ?? 0}',
                        Icons.tag,
                        onTap: () => _showSymbols(context),
                      ),
                    ),
                    SizedBox(
                      width: 400,
                      height: 160,
                      child: _buildResultCard(
                        context,
                        'Arch',
                        '${state.summary?.arch}',
                        Icons.settings_applications,
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

  void _showSymbols(BuildContext context) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) => const SymbolListSheet(),
    );
  }

  Widget _buildErrorCard(BuildContext context, String message) {
    return GlassCard(
      opacity: 0.1,
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Row(
          children: [
            Icon(
              Icons.error_outline,
              color: Theme.of(context).colorScheme.error,
              size: 32,
            ),
            const SizedBox(width: 16),
            Expanded(
              child: Text(
                message,
                style: TextStyle(color: Theme.of(context).colorScheme.error),
                maxLines: 2,
                overflow: TextOverflow.ellipsis,
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
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(label, style: Theme.of(context).textTheme.labelMedium),
                    Text(
                      value,
                      style: Theme.of(context).textTheme.headlineSmall
                          ?.copyWith(fontWeight: FontWeight.bold),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
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
                        ).colorScheme.surfaceVariant.withAlpha(100),
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
