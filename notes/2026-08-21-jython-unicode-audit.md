# Jython Unicode監査

## 決定

Burp/Jython 2では、HTTP由来の生バイト列やJava Stringへ`str()`／`unicode()`を直接適用すると、暗黙のASCII変換で例外になる場合がある。Swing表示・検索・クリップボード用途には`csvlistinput.utils.to_display_text()`を使う。

## 適用範囲

- Parameter & Value Enumのコメント、パス、値の表示
- Packet Grepの結果フィルタ、エラー表示、セルコピー
- Live Grepの検索語保存、セルコピー
- StatisticsのAura集約キー（JSON内のキー・値）
- Color/Comment Snapshotsのメモ表示・例外表示
- HTTP Listener、Decode、右クリック操作、再検出時の例外表示
- Backup & Restoreの日本語CSVセル

## 制約

`to_display_text()`は表示専用である。Insertion Pointの開始・終了オフセット、置換、HTTPバイト列処理には使用せず、既存のbyte-string-spaceヘルパーを使う。

## 検証

UTF-8の日本語バイト列と非UTF-8バイト列の表示変換、Parameter inventory、Aura集約、Backup & Restoreの日本語CSVセルのテストを追加し、全テストを実行した。

## 実ランタイム確認

Burp用のJythonランタイム（`/Users/pentester/work/burp/hython/bin/jython`）で全テストを実行した。Jython固有の失敗を3件検出し、UTF-8テストデータをUnicodeリテラルから生成するよう修正し、旧式の`[SPA(画面更新)]`タグもClear対象へ追加した。Jython・CPythonの双方で47件成功している。
