# MyTools

Burp Suite 用の Jython 拡張です。Repeaterで送るリクエストの複数の項目（URL/Cookie/ヘッダー/JSON・XML本文中の値。入れ子構造も再帰的に展開）に、CSVで用意したテストデータを送信のたびに自動で差し込みます。名前・電話番号・性別などを受け付ける登録APIに、大量のテストデータを1件ずつ流し込むようなテストを想定しています。

詳しい使い方・動作原理は [docs/manual.html](docs/manual.html) を参照してください（ブラウザで開けます）。

## 主な機能

- **Insertion Pointの自動検出** — Burp Scanner相当以上の粒度。URL/Cookie/ヘッダー/`x-www-form-urlencoded`のフィールド/multipartの単純フィールドいずれの値であっても、JSON文字列内に埋め込まれたJSONのような入れ子構造を再帰的に展開して個別の項目として検出します（URLエンコードされている場合も対応）。
- **CSVペイロードリスト** — `No, 項目1, 項目2, ...` 形式（列数可変）を読み込み、検出したInsertion Pointへ手動で列を割り当てます。読み込み後の値はその場で直接編集可能です。
- **自動差し込み** — Active化してRepeaterから送信するたびに、CSVの次の行を消費して差し込みます。開始行の指定・ポインタのリセットに対応。
- **送信ログ** — 実際に送信されたリクエストと、返ってきたレスポンスの両方を確認できます。`#`列の次の**Packet No**列で、その送信がBurpのProxy History上で何番目かも確認できます（Proxyツールを経由しない送信では`-`表示になります）。
- **Session Handling Ruleのマクロ経由の送信にも対応** — マクロが実際に使うツールフラグは手動で有効化する必要があります（詳細はマニュアル参照）。
- **壊れたJSONへの寛容モード（実験的）** — 厳密には正しくないJSONでも、可能な限り値を拾って個別のInsertion Pointにします。
- **Match & Replace** — armする対象とは無関係に、選択したBurpツール（Repeater/Proxyなど）を通る全トラフィックに対して、リクエスト用・レスポンス用それぞれ独立の置換前後文字列リスト（プレーン文字列 or 正規表現、CSV取り込み対応）を適用します。Method/Path/Header/Bodyのどの部分に適用するかも選択可能。実際に置換がヒットした通信だけが同じLogタブに記録され、「Show before Match & Replace」チェックボックスで置換前後のリクエスト/レスポンスを見比べられます。
- **Decode** — 右クリックで選択した文字列（またはタブ内に直接貼り付けた文字列）を、URL/Base64/Hex/HTMLエンティティ/Unicodeエスケープ/ROT13/JWTなど複数の形式で同時にデコード・エンコードして一覧表示します。Burp標準のDecoderのような細長い1件ずつのチェーン操作ではなく、画面幅いっぱいに自動改行しながら全結果を並べて見られます。初期状態では**URL Decodeのみ有効**で、タブ上部のチェックボックスまたはAllボタンで他の変換も有効にできます。左側（元データ）・右側（デコード結果）それぞれに検索欄があり、左側は一致箇所のハイライト＋前後移動、右側は各変換結果内のハイライトに加えて一致しない変換を自動的に非表示にします。左右どちらのテキストを選択して右クリックしても、Match & ReplaceのRequest/Before・Response/Beforeへ追加できます。
- **Target & Replace with Decode & Encode** — Target & List Mappingとは別に右クリックでarmした対象について、特定のInsertion Pointの値を書き換える機能です。値がURL/Base64/Hex/HTMLエンティティ/Unicodeエスケープ/ROT13でエンコードされていても、①デコード → ②指定した文字列（プレーン or 正規表現）で置換 → ③同じ方式で再エンコード、という流れを送信のたびに自動で行ってから送信します。Codecには単体に加え、`URL -> Base64`のような複数段の組み合わせもあり、左から外側→内側の順にデコードし、逆順に再エンコードします。URLデコード後にJSONやフォームの補助文字列が前後に付く場合も、`URL -> Base64`では安全なBase64トークンだけを識別してデコード・置換・再エンコードします。エンコードされたパラメータの中身だけを書き換えたい場合に使います。Insertion Point一覧で行を選択すると、画面下部にOriginal Value（元の値）と、選択中のCodecでデコードした後の値がその場でプレビュー表示されます。実行結果は他の機能と同じくLogタブに記録されます。
- **Errors タブ** — Scanner含むいずれかのBurpツールでの送受信処理中に拡張内部でエラーが起きた場合や、arm・再検出に失敗した場合に、その内容（メッセージ・スタックトレース）を一覧表示します。エラーが1件でもあるとタブ名が赤字で「Errors (件数)」に変わるため、Burp上での動作がおかしいときにすぐ気付けます。
- **Color Snapshots** — Proxy historyの全パケットの色（`setHighlight`。無色も含む）をコメント付きでスナップショットとして丸ごとバックアップし、履歴から選んでリストアできます。全パケットの色を一括で無色に戻す**Clear all colors**もあります。CSV/Match & Replace機能とは独立しており、手動で付けた色分けも対象です。
- **Comment Snapshots** — Proxy history全パケットのCommentをスナップショットとして保存し、選択した時点のコメントへリストアできます。既存Commentを上書きするため、復元前に確認ダイアログを表示します。
- **History Search** — 指定したワードでHTTP History全体（リクエスト・レスポンスの生バイト）を大文字小文字を区別せず検索し、ヒットした前後を指定文字数（既定30文字）だけ切り出して一覧表示します。`hoge & piyo`で同じPacket Noに両方ある通信、`hoge | piyo`でどちらかがある通信を検索できます。演算子を文字として検索する場合は、Windowsでは`\&`・`\|`・`\\`、日本語Macでは`¥&`・`¥|`・`¥¥`でエスケープします（`&`と`|`の混在は不可）。Packet Noの開始・終了を指定すれば、その範囲だけを検索できます（空欄なら全件）。同じパケット内に複数ヒットがあれば、それぞれ別の行として表示されます。Before / Match / Afterはセル単位で選択でき、右クリックからコピーできます。行を選択すると、該当パケットのリクエスト/レスポンスをその場でプレビューでき、リスト下部のプルダウン（既定URL Decode、Noneも選択可）で選んだ方式を選択中の行のBefore/Match/Afterへその場で適用して確認できます。
- **Parameters** — Proxy HTTP Historyのリクエストを、Target & List Mappingと同じJSON/XML・ネスト値対応パーサーで解析し、構造パスごとに重複なく一覧化します。History Searchと同じPacket No rangeで範囲を指定でき、`All`で全件に戻せます。`Clear`で上下の結果を消去します。上下それぞれに検索欄があり、列見出しクリックでソートできます（件数・番号は数値順）。上段のパラメータを選ぶと、下段に値ごとの出現回数・Packet No群を表示し、値を選択してDecode方式を選べば下部でデコード結果も確認できます。アカウント・権限・金銭関連の候補は赤、トークン・識別子・PII候補は黄で強調します（診断時の優先確認用であり、脆弱性の検出結果ではありません）。
- **Statistics** — 指定Packet No範囲（`All`対応）のHistoryを、Web画面／Web個別パーツ取得／SPA（画面）／SPA（画面更新）／APIに分類して件数表示します。AuraのSPA画面更新は、SF Helperと同じく安全な集約キーと履歴順の連続性で代表・集約対象を判定し、集約対象を含む件数／除く件数を比較できます。明示操作で分類・集約タグをCommentへ追記、集約対象へ色付け（既定gray）できます。`Clear annotations`でStatisticsが追加した分類・集約タグだけを削除でき、採番・グループ・その他のタグは保持します。通信は送信しません。
- **Numbering & Grouping** — 採番、採番解除、範囲内のグループ／`[]`タグ削除をStatisticsから分離した専用タブで実行します。右クリックで選択Historyへ`[group="user1"]`形式のグループ定義を追加できます。グループ定義はParametersとHistory Searchの専用Group列へ表示されます。
- **Live Word Watch** — History Searchと同じ形式（List No / Packet No / Req/Resp / Before / Match / After、選択行のプレビュー、Decodeプルダウンでのその場デコード）で、既存のhistoryをまとめて検索するのではなく、**選択したツールを通るリアルタイムの通信**を監視し、指定したワードがヒットした瞬間に1行ずつ追加していきます。Live Word WatchはCommentを持たないため、Group列は表示しません。History Searchと同じく、`&`による同一Packet No内のAND検索、`|`によるOR検索を使えます。演算子を文字として検索する場合は、Windowsでは`\&`・`\|`・`\\`、日本語Macでは`¥&`・`¥|`・`¥¥`でエスケープします。Before / Match / Afterはセル単位で選択し、右クリックからコピーできます。DecodeはNone（変換なし）も選択可能です。armは不要で、Match & Replaceと同様に「Enabled」と対象ツールフラグで動作します。**Scope only**での絞り込み、1通信あたり200件のヒット上限、5MB超の本文のスキップにより、Burp全体への負荷を抑えています。

## 必要環境

- Burp Suite（Community / Professional）
- [jython-standalone.jar](https://www.jython.org/download)

## インストール

1. Burp Suiteの **Extender > Options > Python Environment** で `jython-standalone.jar` を指定する
2. **Extender > Extensions > Add** で Extension type を `Python` にし、このリポジトリの `csv_list_input.py` を選択する
   - `csvlistinput/` フォルダは `csv_list_input.py` と**同じ場所に置いたまま**にしてください。拡張はこのフォルダをパッケージとしてimportするため、`csv_list_input.py` 単体では動作しません。
3. 読み込みに成功すると、Burpのメインウィンドウに **MyTools** タブが追加されます

## 使い方（概要）

Target & List MappingとTarget & Replace with Decode & Encodeは、**それぞれ別々にarmします**（右クリックメニューに専用の項目があります）。同じリクエストを両方に送ってもよいですし、まったく別々のリクエストをそれぞれの機能に割り当てることもできます。

1. テストしたいリクエストをProxy履歴やRepeaterで右クリックし、**Send to Target & List Mapping** でarmする
2. **Target & List Mapping** タブで検出されたInsertion Points一覧を確認する
3. CSVを読み込み、各Insertion Pointに列を対応付ける
4. **Active** を有効にし、対象のツール（通常はRepeater）にチェックを入れる
5. Repeaterから送信すると、CSVの次の行が自動で差し込まれる
6. **Log** タブで、実際に送信された内容とレスポンスを確認する

エンコードされたパラメータの中身だけをピンポイントで書き換えたい場合（CSVは不要）:

1. 対象リクエストを右クリックし、**Send to Target & Replace with Decode & Encode** でarmする（Target & List Mappingとは独立した別の対象として設定されます）
2. **Target & Replace with Decode & Encode** タブで、書き換えたいInsertion Pointの行を選択する。画面下部にOriginal Value（元の値）が表示される
3. その値がエンコードされている場合は **Codec**（None/URL/Base64/Hex/HTML Entity/Unicode \uXXXX/ROT13、または`URL -> Base64`のような複数段Codec）を選ぶ。Codec欄には`URL -> Base64 -> URL`のように3段以上も直接入力でき、左から外側→内側へデコードし、逆順で再エンコードする。選ぶと同時に画面下部のDecoded Value欄にデコード結果がプレビュー表示されるので、正しいCodecを選べているか確認できる。さらに画面下部のPaste text to decodeへ値を貼り付けると、右側に任意のCodec chainで個別デコードした結果を表示できる
4. **Enabled** にチェックを入れ、**Find**（プレーン文字列 or 正規表現、**Regex**チェックで切替）と **Replace With** を入力する
5. タブ最上部の **Target & Replace with Decode & Encode: Enabled** をONにし、対象ツールにチェックを入れる
6. 送信すると、値をデコード → 置換 → 同じ方式で再エンコードしてから送信される。結果は **Log** タブで確認できる

単純な文字列置換だけで良い場合（armは不要）:

1. **Match & Replace** タブで置換前後の文字列を左（リクエスト用）・右（レスポンス用）のリストに手動追加、またはCSV（`Before, After` の2列）で読み込む
2. 対象のツール（Repeater/Proxyなど）とパケット部位（Method/Path/Header/Body）にチェックを入れる
3. 一番上の **Match & Replace: Enabled** をONにする
4. 実際に置換がヒットした通信だけが自動で **Log** タブに記録される（ヒットしなかった通信は表示されない）。行を選択し、Logタブの「Show before Match & Replace」にチェックを入れると置換前の内容に切り替わる

Repeater・Proxy・Logタブなどのリクエスト/レスポンス表示欄で文字列を選択して右クリックすると、**Add selection to Match & Replace → Request/Response Before** でその文字列をBefore列にそのまま追加できます。

同じ右クリックメニューの **Send selection to Decode** を選ぶと、選択した文字列が **Decode** タブに送られ、URL/Base64/Hex/HTMLエンティティ/Unicodeエスケープ/ROT13/JWTなど主要なデコード・エンコード結果が画面いっぱいに一覧表示されます（Burp標準のDecoderタブと違い、1件ずつ変換を選ぶ必要がなく、幅いっぱいに自動改行して表示されます）。

拡張内部でエラーが起きた場合（Scannerなどのトラフィック処理中の例外、arm・再検出の失敗など）は **Errors** タブに自動で記録されます。1件でもあるとタブ名が赤字で「Errors (件数)」に変わるので、Burp上での動作がおかしいときはまずこのタブを確認してください。行を選択するとエラーメッセージとスタックトレースの詳細が下部に表示されます。

Proxy historyの色分け状態をまるごと退避しておきたい場合:

1. **Color Snapshots** タブでコメント（任意）を入力し、**Take snapshot** を押す。その時点でProxy historyにある全パケットの色（無色も含む）が1件のスナップショットとして記録される
2. 何度でも取得でき、一覧表に（No / 日時 / コメント / 色あり件数）として積み上がる
3. 一覧からスナップショットを選択し、**Restore selected** を押す（確認ダイアログが出ます）と、そのスナップショット取得時点に存在したパケットの色が当時の状態に一括で戻る（取得後に増えた通信には触れない）
4. 不要なスナップショットは選択して **Delete selected** で履歴から削除できる
5. **Clear all colors** を押す（確認ダイアログが出ます）と、Proxy history上の全パケットの色を一括で無色に戻せる

> ⚠️ リストア・Clear all colorsはどちらも元に戻せません。現在の色分けを失いたくない場合は、実行前に現在の状態もスナップショットしておいてください。スナップショットはメモリ上のみの保持で、拡張のリロード/アンロードで消えます。

Proxy history全体から特定のワードを検索したい場合:

1. **History Search** タブの **Search word** にワードを入力する
2. **Chars before** / **Chars after** で、ヒット箇所の前後それぞれ何文字を切り出すかを指定する（既定はどちらも30文字）
3. 必要ならPacket Noの開始・終了を指定する（空欄または**All**で全件）。`hoge & piyo`で同一Packet No内のAND、`hoge | piyo`でOR。記号を文字として探す場合はWindowsで`\&`/`\|`/`\\`、日本語Macで`¥&`/`¥|`/`¥¥`を使う
4. **Search** を押すと、指定範囲のProxy history（リクエスト・レスポンスの生バイト）を大文字小文字を区別せず検索する
5. 結果は一覧表（List No / Packet No / Req/Resp / Before / Match / After）に、ヒットごとに1行ずつ表示される。Before / Match / Afterはセル単位で選択でき、右クリックの**Copy selected cell**でコピーできる
6. 行を選択すると、下部にそのパケットのリクエスト/レスポンスがプレビュー表示される（該当箇所はBurp標準のメッセージビューア内検索で探せます）
7. リストのすぐ下にある **Decode** プルダウン（`None`またはURL Decode等）で方式を選ぶと、その右側に選択中の行のBefore/Match/Afterそれぞれへその方式を適用した結果がその場で表示される
8. **Clear** を押すと結果一覧だけがクリアされる（**Search word**・**Chars before**・**Chars after**の入力値はそのまま保持されます）

Proxy historyのリクエストパラメータを集計したい場合:

1. **Parameters** タブの **Range...** から対象Packet No範囲を設定する（既定は全HTTP History）
2. **Build parameter list** を押す
3. 構造パス、出現回数、出現Packet No群を確認する。赤は認可・アカウント・金銭関連、黄は識別子・トークン・PII候補で、診断の優先確認用の目印です

リアルタイムの通信を監視して、ワードがヒットした瞬間に確認したい場合:

1. **Live Word Watch** タブの **Search word** にワードを入力し、必要なら **Chars before** / **Chars after** も調整する（既定はどちらも30文字）
2. **Tool flags to watch** で監視対象のツール（既定はRepeaterのみ）にチェックを入れる
3. Proxyツールを監視対象に含める場合は、**Scope only** のONを強く推奨します（Burpの Target &gt; Scope で対象ホストを設定しておいてください）。ONにすると、Scope外の通信（広告・トラッキング・CDN等、閲覧中に大量に発生する無関係な通信）を本文の変換・検索より前の段階でスキップします
4. **Live Word Watch: Enabled** をONにする
5. 対象ツールを通る通信でワードがヒットするたびに、結果一覧（History Searchと同じ List No / Packet No / Req/Resp / Before / Match / After 形式）に自動で行が追加されていく
6. 行を選択するとリクエスト/レスポンスのプレビューと、下部のDecodeプルダウンによるその場デコードが利用できる（History Searchと同じ操作感）
7. **Search word**・**Chars before**・**Chars after**・監視対象ツール・**Scope only**はEnabled中でも編集でき、次に処理される通信から即座に反映される（Match & Replaceのルール編集と同じ考え方）
8. **Clear** を押すと結果一覧だけがクリアされる（設定値は保持されます）

> ⚠️ **パフォーマンス上の注意（Burp全体のフリーズ防止のための制限）**
> - 短い/よくある文字列（例: 1文字の"e"等）をワードに指定すると、大きなレスポンス1件だけで数千〜数万件
>   ヒットすることがあります。**1通信あたりのヒット数は200件まで**に制限しています（超えた分は記録されません）。
> - **5MBを超えるリクエスト/レスポンス本文は検索対象外**です（動画・大きな画像・ダウンロード等をそのまま
>   文字列変換・検索してしまうコストを避けるため）。
> - **Proxyツールを監視対象にしたまま通常のブラウジングを行うと、広告・トラッキング・CDN等を含む大量の
>   通信すべてが検索対象になり、Burp全体の動作が重くなることがあります。** 上記の**Scope only**を有効にし、
>   Target Scopeで対象ホストを絞り込んでおくことを強く推奨します。
> - 実用上は、ある程度絞り込んだ具体的な文字列をワードに指定することも推奨します。

詳細な手順・画面の見方・動作原理・トラブルシューティングは [docs/manual.html](docs/manual.html) にまとまっています。

## ディレクトリ構成

```
csv_list_input.py          # Burp拡張のエントリポイント（薄い配線のみ）
csvlistinput/               # 拡張の実装本体 -- csv_list_input.py と同じ場所に必須
  json_offset_parser.py     # JSON再帰オフセットパーサー（厳密パース／寛容パース／総当たり補完）
  xml_offset_scanner.py     # XMLのオフセット付きスキャナー
  multipart_decomposer.py   # multipart/form-data の分解
  detection_engine.py       # Insertion Point検出の統括
  substitution_engine.py    # 差し替え（バイト列スプライシング）
  matching.py                # arm時テンプレートとlive送信のpathベース突き合わせ
  csv_payload_store.py       # CSV読み込み・行ポインタ管理
  armed_target.py             # 対象通信・マッピング設定の保持（Target & List Mapping用、Target & Replace with Decode & Encode用でそれぞれ1個ずつインスタンス化）
  http_listener.py             # 送信時の割り込み・差し込み処理
  context_menu.py              # 右クリックメニュー（Target & List Mapping / Target & Replace with Decode & Encodeをそれぞれ個別にarm）
  log_store.py                  # 送信ログの保持
  error_store.py                 # Errorsタブの保持
  replace_settings.py            # Match & Replace: 有効/無効・対象ツール・対象パケット部位
  replace_rule_store.py           # Match & Replace: 置換前後リストの保持・CSV読み込み
  packet_regions.py                # Method/Path/Header/Bodyのバイトオフセット区間算出
  replace_engine.py                 # Match & Replace: ルール適用ロジック
  decode_engine.py                   # Decodeタブ: URL/Base64/Hex/HTML/Unicode/ROT13/JWT等の変換ロジック（表示用、実Unicode）
  codec_engine.py                     # Target & Replace with Decode & Encode用のバイト列ネイティブなencode/decode対
  decode_replace_engine.py             # Target & Replace with Decode & Encode: デコード→置換→再エンコードの適用ロジック
  decode_replace_settings.py            # Target & Replace with Decode & Encode: 有効/無効・対象ツール・Insertion Point毎のルール保持
  color_snapshot_store.py                # Color Snapshots: スナップショット履歴の保持
  color_snapshot_engine.py                # Color Snapshots: Proxy historyの色の読み取り/書き戻し
  word_search_engine.py                    # History Search: Proxy historyの生バイトに対するワード検索・前後切り出し（Live Word Watchとも共有）
  proxy_history_lookup.py                   # Log / Live Word Watch共通: (http_service, request)からProxy History上の位置を逆引き
  live_word_watch_settings.py                # Live Word Watch: 有効/無効・検索ワード・前後文字数・対象ツール
  live_word_watch_store.py                    # Live Word Watch: ヒット履歴の保持
  live_word_watch_listener.py                  # Live Word Watch: IHttpListener実装（ライブ通信の監視・ヒット検出）
  utils.py                       # バイト列/文字列境界の処理・エスケープ
  ui/                              # Swing UI（Target & List Mapping / Target & Replace with Decode & Encode / Match & Replace / Log / Color Snapshots / History Search / Live Word Watch / Decode / Errors タブ）
docs/manual.html              # 利用マニュアル（HTML）
testdata/                      # 動作確認用のサンプルリクエスト・CSV
```

## 制限事項

- Target & List Mapping、Target & Replace with Decode & Encode、それぞれについて同時にarmできる対象は1つだけです（例えばTarget & List Mappingで2つ以上の対象を並行してテストすることはできません。ただし2つの機能同士は互いに独立しているので、Target & List Mapping用に1つ、Target & Replace with Decode & Encode用に別の1つ、という組み合わせは可能です）
- Base64やURLエンコードされた中に、さらに奥にJSON/XMLが埋め込まれている場合、Insertion Point検出はそれを自動では個別の項目に展開しません（Target & Replace with Decode & Encodeで、そのInsertion Point全体をデコード→置換→再エンコード対象として手動指定することは可能です）
- 壊れたJSONの寛容モードは実験的機能で、真の入れ子構造までは保証されません
- 同じ要素内でテキストと子要素が混在するXML（mixed content）は、テキスト部分ごとに別のInsertion Pointとして扱われます
- Target & Replace with Decode & Encodeは、armした自分自身の対象にのみ適用されます（Match & Replaceのようなトラフィック全体への適用はしません）

詳しくは [docs/manual.html](docs/manual.html) の「制限事項」を参照してください。
