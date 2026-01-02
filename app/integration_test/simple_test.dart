import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:kernel_lens_app/src/app.dart';
import 'package:kernel_lens_app/src/rust/frb_generated.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => await RustLib.init());
  testWidgets('Can load analysis dashboard', (WidgetTester tester) async {
    await tester.pumpWidget(const ProviderScope(child: KernelLensApp()));
    expect(find.text('Kernel Analysis'), findsOneWidget);
  });
}
