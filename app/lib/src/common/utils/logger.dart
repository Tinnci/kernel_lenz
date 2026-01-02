import 'package:flutter/foundation.dart';
import 'package:logger/logger.dart';

/// 2026 Flutter Logging Best Practice Implementation
/// Supports leveled logging, environment filtering, and pretty console output.
class AppLogger {
  static final Logger _logger = Logger(
    printer: PrettyPrinter(
      methodCount: 2, // 展示调用栈深度
      errorMethodCount: 8, // 错误时展示更深的调用栈
      lineLength: 120, // 每行长度
      colors: true, // 彩色输出
      printEmojis: true, // 打印表情符号
      dateTimeFormat: DateTimeFormat.dateAndTime, // 展示时间
    ),
    // 2026 最佳实践：生产环境仅记录 Warning 及以上等级
    level: kDebugMode ? Level.trace : Level.warning,
  );

  /// 详细信息 (Verbose/Trace) - 极细颗粒度
  static void v(String message, [dynamic error, StackTrace? stackTrace]) =>
      _logger.t(message, error: error, stackTrace: stackTrace);

  /// 调试信息 (Debug) - 开发时状态
  static void d(String message, [dynamic error, StackTrace? stackTrace]) =>
      _logger.d(message, error: error, stackTrace: stackTrace);

  /// 业务流信息 (Info) - 关键节点
  static void i(String message, [dynamic error, StackTrace? stackTrace]) =>
      _logger.i(message, error: error, stackTrace: stackTrace);

  /// 警告信息 (Warning) - 非预期但可继续
  static void w(String message, [dynamic error, StackTrace? stackTrace]) =>
      _logger.w(message, error: error, stackTrace: stackTrace);

  /// 错误信息 (Error) - 功能不可用
  static void e(String message, [dynamic error, StackTrace? stackTrace]) =>
      _logger.e(message, error: error, stackTrace: stackTrace);

  /// 灾难性错误 (Fatal) - 应用崩溃
  static void f(String message, [dynamic error, StackTrace? stackTrace]) =>
      _logger.f(message, error: error, stackTrace: stackTrace);
}
