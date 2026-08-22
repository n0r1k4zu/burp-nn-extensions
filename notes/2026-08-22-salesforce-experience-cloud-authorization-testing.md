# Salesforce Experience Cloud / Aura 認可診断の効率化設計

作成日: 2026-08-22  
対象: 許可を得たWebアプリケーション脆弱性診断  
目的: Burp Suiteを用いた動的認可テストの実務手順と、MyToolsへ将来実装する際の要件整理

## 結論

全HTTPパケットの全Insertion Pointを機械的に総当たりしても、認可診断の網羅性は上がりにくい。認可は単なる値の妥当性ではなく、次の関係で決まるためである。

```text
Subject（誰が） × Operation（何をする） × Resource（何に対して） × Context（どの状態で）
```

有効な方法は、通信をAura actionまたはAPI operation単位へ正規化し、同型通信を重複排除した上で、所有関係が分かるテストデータを異なるSubjectのセッションで再送する差分テストである。最初はRead/List/Search/Downloadを広く安全に試し、Update/Delete/Approve等は専用データと明示的承認の下で限定実行する。

BurpだけからSalesforce設定やApexコードの欠陥を断定することはできない。動的試験は不正な結果を実証し、疑わしい制御層を絞る。最終的な根本原因の確定には、External OWD、Sharing Rule/Set、Profile/Permission Set、Guest設定、Apex API version、sharing宣言、DB access mode、業務認可ロジックの確認を組み合わせる。

## 実装状況（2026-08-23更新）

この設計のPhase 1に当たる受動解析を、MyToolsの`Authorization Planning`タブとして実装した。

- 指定Packet No範囲またはHTTP History全体をバックグラウンド解析し、Cancelと進捗表示に対応。任意の`Target scope only`（既定OFF）でBurp Target scope内へ限定可能
- Overview / Operation Catalog / Operation x Subject / Objects & Fields / Apps & Endpoints / Test Plan / Sessions / Planning Coverage / Technical Gaps / Resource Corpusの10画面
- Aura batchをaction単位へ分離し、Salesforce標準／組織カスタムApex／管理・名前空間付きApex／不明を根拠付きで分類
- Origin（実装由来）とData Interaction（Record Read/List/Create/Update/Delete等）を分離し、Originをリスクスコアへ加点しない
- Aura内／通常のGraphQLからquery・mutation・Object・Field・filter・pagination・CRUD意図を抽出
- Subject×Operationは観測済みの疎な行列だけを表示し、未観測をDeniedとは扱わない
- Object/Field、App/Aura endpoint、Salesforce featureを専用catalogへ整理し、テスト計画上の不足と機械解析上の不足を別画面に分離
- Aura以外の対象システム固有経路もAll HTTP Endpointsへ収録し、Packet Coverageで全解析PacketからOperationへの到達を監査する。未到達はTechnical Gapへ記録する
- 物理的な宛先基盤はHTTPだけから推定せず、仕様書等に基づくDestination ruleへ一致した場合だけOn-prem等の利用者定義ラベルを表示する
- 既存Insertion Point検出器、リクエスト／レスポンス構造、Group、Statistics分類、Resource候補を横断集約
- Cookie、Authorization、CSRF、Aura tokenの生値はカタログ列へ複製せず、SessionはSHA-256指紋で表示（代表通信のBurpビューアは元のHistoryを表示）
- 日本語URL・Comment・Group・JSONを含むCPython/Jython回帰試験を追加

この段階ではHTTP再送、History変更、脆弱性の自動判定を行わない。これは安全な棚卸しとテスト仮説作成を先に独立させ、後続の差分再送で誤ったSubject／Resourceの組合せを作らないための決定である。

### Aura origin分類の実装上の基準

`Authorization Planning`のOriginは通信からの推定であり、Salesforce設定やApexコードを読んだ確定結果ではない。`aura://`および`servicecomponent://`のdescriptor schemeは`Salesforce Standard`（high）、`apex://`の明示namespaceなしのcontrollerは`Org Custom Apex`（medium）、明示namespaceありは`Managed or Namespaced Apex`（medium）へ分類する。`lightning`、`ui`、`force`、`communities`、`community`、`siteforce`、`visualforce`、`applauncher`、`salesforce`、`sfdc`は代表的なSalesforce namespaceとして`Salesforce Standard`（medium）へ寄せるが、この集合は完全な公式一覧ではない。

`aura://ApexActionController/ACTION$execute`では、`params.classname`／`apexClass`／`className`と`params.namespace`で同じ分類を行い、`params.method`／`methodName`はOperation名の補助に使う。schemeが欠落・未認識、またはこの汎用入口でclass／namespaceが得られない場合は`Unknown`（low）である。confidenceは分類根拠の直接性であって、認可設定・Apex実装の安全性や脆弱性の確率を示さない。`callingDescriptor`とaction IDはOperationの識別・追跡には使うが、Origin判定の決め手ではない。

## 認可制御の層

| 制御層 | 主な設定・実装 | 主な失敗例 |
|---|---|---|
| Site membership | Experience Cloud Members | 広すぎるProfile/Permission Setを会員にする |
| 表示制御 | Experience Builder Audience/Page Variation | UI非表示をサーバ側認可と誤認する |
| Apex class access | Profile / Permission Set | 外部ユーザまたはGuestへ不要なクラスを許可する |
| Object CRUD | Profile / Permission Set | Readだけの主体がCreate/Update/Deleteできる |
| Field-level security (FLS) | Profile / Permission Set | 非許可項目を読める、または更新できる |
| Record sharing | External OWD、Sharing Rule、Sharing Set、Role、Manual/Apex sharing | 他人・他社・別Accountのレコードへ到達できる |
| Apex execution context | `with/without/inherited sharing`、user/system mode | 設定済みの共有・CRUD・FLSをカスタム処理が迂回する |
| Business authorization | カスタムApex、Flow、Trigger等 | 他人の承認、金額変更、不正な状態遷移を許可する |

`with sharing`はレコードレベルの共有を扱うが、CRUD/FLSの保証とは別である。Salesforce公式もこの分離を明記している。[Secure Apex Classes](https://developer.salesforce.com/docs/platform/lwc/guide/apex-security)

API versionにも注意する。2026年8月時点の公式資料では、API 67.0以降は安全側の既定動作が強化されている一方、API 66.0以前のApexはsystem modeを前提に評価する必要がある。クラスのコンパイルAPI versionと、個々のSOQL/DMLに指定されたuser/system modeを確認する。

## Salesforce設定側の確認項目

### External OWDと共有

- External Organization-Wide Defaultsが非公開データに対して`Private`か
- Sharing Ruleが外部ロール、Portal Subordinates、公開グループへ過剰に開いていないか
- Sharing SetのUser側Account/ContactとTarget Record側のマッピングが意図どおりか
- Sharing SetがRead/Writeを不要に付与していないか
- Permission Setの加算結果で想定以上の権限になっていないか
- 古い組織の外部共有設定が安全側へ移行済みか
- Userオブジェクトの可視性と個人情報項目が外部ユーザ間で適切か

Sharing Setは、外部ユーザのAccount/Contactと対象レコードの関係に基づきアクセスを付与する。[Create a Sharing Set for Experience Cloud Site Users](https://help.salesforce.com/s/articleView?id=sf.networks_setting_light_users.htm&language=en_US&type=5) また、Experience Cloudライセンスにより利用可能な共有モデルが異なるため、同じ「外部ユーザ」でも一種類として扱わない。[Sharing CRM Data in an Experience Cloud Site](https://help.salesforce.com/s/articleView?id=experience.networks_sharing_CRM_data_cheatsheet.htm&language=en_US&type=5)

### Guest

- Guest User ProfileのCRUD/FLS
- Guestに許可されたApex class
- Guest User Sharing Rule
- 公開API、ファイル、ユーザ検索、自己登録
- Guest入力をsystem modeで処理して結果を返すカスタムApex
- Guest User Sharing Rule Access Reportの結果

Experience CloudはサイトごとにGuest User ProfileとGuest User Recordを持つ。[Give Secure Access to Unauthenticated Users](https://help.salesforce.com/s/articleView?id=platform.networks_public_access.htm&language=en_US) Guestは匿名利用者全体で一つの主体を共有するため、個人ごとの所有者照合をGuestセッションそのものへ依存させてはいけない。

### Apexとカスタムロジック

- `without sharing`
- 呼出し経路で意味が変わる`inherited sharing`
- `WITH SYSTEM_MODE`やsystem mode DML
- `WITH USER_MODE`、`Security.stripInaccessible()`、DescribeによるCRUD/FLS検査の欠落
- クライアント由来のrecord/account/contact/owner/parent IDを照合せずSOQL/DMLへ渡す処理
- DTOやsObjectを丸ごとdeserializationして更新する処理
- `status`、`amount`、`role`、`isApproved`等をクライアントの申告だけで信頼する処理
- 動的なobject/field/filter指定
- 親だけを確認し、子・添付ファイル・ContentDocument等を確認しない処理
- Queueable/Future/Flow/Trigger等へ処理が渡った後の権限文脈

認証済みユーザまたはGuestが`@AuraEnabled`メソッドへ到達するにはApex class accessが必要だが、クラスへ到達可能であることと、各データ操作が安全であることは別問題である。[Secure Apex Classes](https://developer.salesforce.com/docs/platform/lwc/guide/apex-security) `@AuraEnabled`メソッドはプリミティブだけでなくsObject、独自型、Collectionを入出力できるため、ネストDTOや配列も認可試験の対象になる。[Expose Apex Methods to Components](https://developer.salesforce.com/docs/platform/lwc/guide/apex-expose-method.html)

## Burpでの試験モデル

### Subject

最低限、次の主体を用意する。

1. Guest
2. 外部ユーザA（テストレコードAの所有者または正当な利用者）
3. Aと同じAccount/Contact範囲の外部ユーザB
4. 別Accountまたは別テナントの外部ユーザC
5. 異なるProfile / Permission Set / Role / Licenseの外部ユーザ
6. 制限付き内部ユーザ
7. 管理者または正当な高権限ユーザ（期待結果の確認用）

同じ権限のA/Bは水平認可、低権限/高権限は垂直認可、A/Cはテナント境界を試すために必要となる。PortSwiggerも同権限の二ユーザによるセッション差替えと、異なるセッションでのSite map比較を認可テスト手順として案内している。[Testing horizontal access controls](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/access-controls/horizontal-access-controls) [Comparing site maps](https://portswigger.net/burp/documentation/desktop/tools/target/site-map/comparing)

### Operation

HTTPパケットではなく、サーバ側の操作を単位にする。

- Aura: `actions[n].descriptor` + parameter path schema
- REST: method + normalized path + request schema
- GraphQL: operationName + root field + selection/input schema
- UI API/LDS: operation種別 + object + record/field schema
- ファイル: metadata/read/download/upload/delete
- 業務操作: approve/reject/cancel/refund/export/impersonate等

Auraは一つのHTTP POSTへ複数actionを含み得る。そのため、パケット一件を一操作として数えず、`actions[]`を分解する。Auraの内部wire protocolを網羅した安定版の公式仕様は確認できなかったため、観測形式への依存はProtocol Adapterへ隔離し、Salesforce側の変更に追随可能にする。

### Resource

- 15/18文字のSalesforce IDらしい値。ただし長さだけで断定せず、応答・別セッションで観測した由来を保持する
- `recordId`、`accountId`、`contactId`、`ownerId`、`parentId`、`userId`等
- ID配列、ネストDTO内ID、文字列化JSON内ID
- Object/Field selector: `objectApiName`、`fieldApiName`、`fields`
- Scope selector: `filter`、`query`、`search`、`limit`、`offset`
- Mutation control: `status`、`amount`、`role`、`approval`等
- ファイルや関係レコードのID

OWASPは、オブジェクト識別子がpath/queryだけでなくheaderやrequest bodyにも存在し得るとしている。[API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) さらに、レコード単位だけでなく、読める項目・更新できる項目の検査も必要である。[API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)

### 変えてはいけない制御値

通常の認可候補から、次を既定除外する。

- Session Cookie / Authorization token
- CSRF token / nonce
- `aura.context`
- `fwuid`
- `aura.token`
- Aura action ID、トレースID、時刻等

これらはSubject切替やリクエスト成立のために、別のSession Adapterが整合性を保つ。通常のInsertion Pointと同じ総当たりに入れると、認可拒否ではなく壊れた要求を大量生成する。

## 実務手順

### 1. スコープと安全条件を固定する

- Burp Scope内のみ
- 診断専用ユーザと診断専用レコード
- Read-onlyを既定
- 最大要求数、同時実行数、遅延、停止条件
- ログイン、ログアウト、退会、削除、送金、承認、外部通知を既定除外
- 書込み試験は個別allowlistと実行前確認

### 2. 各Subjectで正常系を収集する

同じ業務シナリオをA/B/C/Guest等で実行し、Proxy historyへ主体タグを付ける。BurpのSession handling ruleとmacroは、セッション維持やCSRF tokenの再取得に利用できる。[Sessions settings](https://portswigger.net/burp/documentation/desktop/settings/sessions) [Session handling rule editor](https://portswigger.net/burp/documentation/desktop/settings/sessions/session-handling-rules)

### 3. Operation Catalogへ正規化する

同一descriptor、同一parameter path schema、同一read/write性の通信を一つへ集約し、代表パケットを選ぶ。値だけが違う画面更新を全件再送しない。

```text
OperationKey = host + site path + protocol + descriptor/method + parameter path schema
```

### 4. Resource Corpusを作る

各値に由来を持たせる。

```text
value
semantic type
source subject
owner/account/tenant relation
source packet/response path
confidence
safe test record flag
```

ランダムなIDを投げるより、A所有、同一AccountのB所有、別AccountのC所有、管理者のみ可視という既知の値を使う方が、認可境界を判定できる。

### 5. 差分再送する

1. AがA所有リソースへ行う正常要求をbaselineにする
2. SubjectだけをB/C/Guestへ替える
3. ResourceだけをA/B/C由来へ替える
4. 一度に一つの意味パラメータを替える
5. ID配列は各要素、一部混在、全置換を分ける
6. 必要に応じて`null`、省略、空配列でサーバの暗黙範囲を確認する
7. HTTP methodやoperationの違いも別テストとして扱う

単一差替えで拒否された場合も、直ちに安全とは結論しない。`recordId`と`accountId`、親IDと子IDなど、サーバが複数値の整合性を検査している可能性がある。第二段階では、同じ主体の通信・応答で共起した値を`ResourceBundle`として扱い、観測された整合した組だけをまとめて差し替える。無関係な値の全組合せは作らない。

OWASPはAの専用リソースをBのアカウントで操作する試験をBOLAの基本手順としている。[WSTG API Broken Object Level Authorization](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization/)

### 6. 応答と副作用を意味比較する

HTTP statusだけでは判定しない。

- Aura `state` / `errors` / `returnValue`
- JSONのキー集合、レコードID集合、件数、機微項目
- Redirect先、ログイン画面化
- response length/hash。ただし補助指標に限定
- ownerセッションから見た更新・削除・承認等の副作用
- 非同期処理の完了後状態

揮発値、action ID、timestamp、trace ID、順序差を正規化してから比較する。HTTP 200でも他人のデータが含まれれば不備になり得る。HTTP 500は拒否の証拠とは限らない。

### 7. 人が判定する

Burp公式も、Site map差分はアプリケーションの機能・文脈を理解して解釈する必要があり、完全自動判定には限界があるとしている。[Site map comparison results](https://portswigger.net/burp/documentation/desktop/tools/target/site-map/comparison-results)

最終状態は次の4値とする。

- `CONFIRMED`: 期待上拒否される主体が対象データまたは副作用を取得し、証拠を再現できた
- `SUSPECTED`: baselineに近い応答や機微情報の兆候があるが、業務期待または副作用が未確認
- `DENIED`: 明確な拒否または不許可データが含まれない
- `INCONCLUSIVE`: セッション切れ、リクエスト破損、レート制限、非同期、期待ポリシー未定義等

## 分量を減らすアルゴリズム

### 総当たりをしない理由

パケット数を`P`、Insertion Point数を`I`、Subject数を`S`、候補値数を`V`とすると、単純な再送は概ね`P × I × S × V`となる。Aura batch、画面更新、共通token、同型要求が多数含まれるため、要求数の大半は重複か無意味な破損要求になる。

### 縮約手順

1. 静的asset、telemetry、framework controlを除外
2. HTTPではなくAura action/API operationへ分解
3. OperationKeyで同型通信を重複排除
4. parameter pathを意味分類し、認可関連候補だけを残す
5. Resource Corpusの所有関係が判明した値だけを優先
6. Read系を先行し、書込み系は承認待ちにする
7. 同じparameter path・同じ制御層・同じ応答schemaの代表操作を先に試す
8. 異常が出たclusterだけ深掘りする
9. 新しいdescriptor/path/schemaが出た時だけ増分試験する

### 候補スコア例

```text
+40 別Account/別tenant由来と確認済みのID
+35 owner/account/contact/parent/user/file/payment等の関係ID
+30 Update/Delete/Approve/Refund/Export操作
+25 ID配列またはネストDTO内のID
+20 object/field/filter selector
+15 一覧・検索・集計・件数取得
+10 responseで後続requestへ伝播した値
-50 session/CSRF/Aura framework control
-30 static asset/telemetry
-20 値の由来がなくランダムである
```

スコアは脆弱性判定ではなく、限られたテスト予算の順序付けにのみ使う。

## MyToolsへ実装する場合の構成

既存のAuthorization機能は過去に削除されているため、この文書は新しいopt-inモジュールの設計案であり、無断で旧機能を復活させるものではない。

### 再利用できる既存機能

- `DetectionEngine`: URL/Cookie/Header/form/multipart/JSON/XML/NDJSON、percent decode、文字列化JSON/XML、byte offset
- `Parameter & Value Enum`: parameter path、値、領域、Packet No、出現回数
- `Aura Diagnostic`: Aura session/action/response処理の一部
- `Statistics`: Aura周辺通信の集約
- `Packet Grep` / `My Word List Grep`: 候補値とレスポンス追跡
- 右クリックのPacket & Insertion Point CSV export

### 新規に必要な層

#### Protocol Adapter

- Aura form bodyの`message.actions[]`分解
- descriptor、callingDescriptor、paramsの抽出
- batchから一actionだけ変更し、他actionを保持するrequest builder
- REST / GraphQL / UI API / fileのadapter
- framework controlと業務入力の分離

#### Subject & Session Vault

- Subject名、role/profile/license/account/tenantのメタデータ
- Cookie/header/token差替え
- Session validationと更新hook
- 認証情報そのものを平文永続化しない
- 実行時に「実際にどのSubjectだったか」を応答で検証する

#### Operation Catalog

```text
operation_id
protocol
host/site
descriptor or method/path
parameter schema
observed subjects
read/write classification
representative packets
response schema
```

#### Resource Corpus

```text
resource_id/value
semantic type
Salesforce object candidate
owner subject
account/tenant relation
provenance packet/path
confidence
safe test data flag
```

関連値は次のbundleとしても保持する。

```text
ResourceBundle
  primary record ID
  object type
  owner subject
  Account / Contact / Owner / Parent IDs
  child and file IDs
  provenance packets and paths
```

#### Policy Matrix

OWASPのauthorization matrixを、次の機械可読形式へ拡張する。[Authorization Testing Automation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html)

```yaml
- subject: external_user_a
  operation: CaseController.getCase
  resource_relation: other_account
  action: read
  expected: deny
```

期待結果が未定義の組合せは自動的に脆弱と断定せず、`INCONCLUSIVE`またはレビュー待ちにする。

#### Replay Planner

- 一parameter差分
- Subject差分
- 所有関係別value選択
- pairwise優先と予算管理
- read-only / write gated queue
- Scope、rate、concurrency、cancel
- baseline再確認とsession validity確認

#### Semantic Diff

- JSON/Aura正規化
- ID/field/count leakage
- error/login/rate-limit分類
- 副作用確認hook
- `CONFIRMED / SUSPECTED / DENIED / INCONCLUSIVE`

#### Evidence

```text
Subject
Original packet
Operation / Aura descriptor
Parameter JSON path
Original value
Replacement value and provenance
Expected policy
Normalized response difference
Side-effect evidence
Suspected Salesforce control layer
```

疑わしい制御層は次のように案内できるが、断定しない。

- 標準UI API/LDSでも漏れる: OWD / Sharing / CRUD / FLS候補
- カスタムApexだけ漏れる: sharing宣言 / DB mode / CRUD/FLS / 業務ロジック候補
- Guestだけ漏れる: Guest Profile / Guest Sharing Rule / Guest許可Apex候補
- UIでは非表示だが直接actionを呼べる: Audienceを認可境界に使った可能性
- Class呼出しは可能だが特定recordだけ漏れる: record/business authorization候補

## UI案

1. `Subjects`: 主体とセッション状態
2. `Operation Catalog`: descriptor/API operation、schema、代表Packet
3. `Resource Corpus`: 値、所有者、Account/Tenant、由来
4. `Policy Matrix`: Allow/Deny/未定義
5. `Test Plan`: 予算、read-only、除外、rate、対象Scope
6. `Results`: 4値判定、差分、疑わしい制御層
7. `Evidence`: original/modified request、response、再現手順

## 実装段階

### Phase 1: Passive Catalog

送信しない。HistoryからAura action/API operation、parameter schema、ID候補、値の由来を棚卸しする。

受入基準:

- 同一Aura descriptor/schemaが重複排除される
- batch内actionが個別表示される
- ネスト/文字列化JSON内のpathとbyte offsetが保持される
- framework controlが既定除外される
- 解析失敗したpacketが明示され、黙って消えない

### Phase 2: Subject / Resource labeling

利用者が主体とテストデータ所有関係を確認・修正できる。

受入基準:

- 各valueにprovenanceがある
- 同一Account/別Account/別tenantを区別できる
- credentialsを永続化しない

### Phase 3: Read-only differential replay

Read/List/Search/Downloadの許可済み対象だけを低並列で再送する。

受入基準:

- セッション切れを成功扱いしない
- baseline不成立時はテストを中止する
- 1操作1パラメータ差分を証跡化する
- HTTP 200だけで脆弱と断定しない
- Cancelが速やかに効く

### Phase 4: Write-gated scenarios

専用データ、明示allowlist、確認dialog、副作用検証、可能ならcleanupを備える。

### Phase 5: Regression

確認済みPolicy Matrixを保存し、新しいdescriptor/schemaまたは挙動差だけを増分試験する。OWASPもActor/Resource/Actionの機械可読マトリクスによる継続的な認可回帰試験を推奨している。[Authorization Regression Testing Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html)

### Coverage表示

ツールは「全認可を検査済み」と表示してはいけない。次を分母・分子として明示する。

- 観測済みOperation数 / 実行済みOperation数
- 登録Subject pair数 / 実行済みSubject pair数
- 候補parameter path数 / 実行済みpath数
- 収集Resource class数 / 試験済みrelation数
- 未検査理由（履歴未観測、期待ポリシー未定義、write gate、session失効、予算超過等）

## 限界と判断上の注意

- HTTPで一度も現れないサーバ側機能・項目は、Historyだけから完全列挙できない
- 画面に見えないことは拒否の証拠ではない
- 成功に見える200応答でも空データ、public data、cache、共通データの場合がある
- 403と500の違いだけでは根本原因を確定できない
- Guest、同一Account、別Account、別licenseを一種類の低権限ユーザで代用できない
- Subject間でCookie、CSRF、Aura tokenが混在した場合、その結果はすべて無効とする
- Standard UI APIとcustom Apexの差は原因推定に役立つが、設定・コード確認なしに断定しない
- 「全パラメータを試した」は「全認可ルールを試した」と同義ではない
- 自動化の価値は脆弱性を自動断定することではなく、重複除去、正しい値の組合せ、セッション整合性、証跡作成にある

## 主要資料

- [Salesforce: Secure Apex Classes](https://developer.salesforce.com/docs/platform/lwc/guide/apex-security)
- [Salesforce: Permissions and Access Settings](https://developer.salesforce.com/docs/atlas.en-us.securityImplGuide.meta/securityImplGuide/permissions_about_users_access.htm)
- [Salesforce: Sharing and Record Access Features](https://help.salesforce.com/s/articleView?id=sf.managing_the_sharing_model.htm&language=en_US&type=5)
- [Salesforce: Create a Sharing Set for Experience Cloud Site Users](https://help.salesforce.com/s/articleView?id=sf.networks_setting_light_users.htm&language=en_US&type=5)
- [Salesforce: Give Secure Access to Unauthenticated Users](https://help.salesforce.com/s/articleView?id=platform.networks_public_access.htm&language=en_US)
- [PortSwigger: Testing access controls with Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/access-controls)
- [PortSwigger: Comparing site maps](https://portswigger.net/burp/documentation/desktop/tools/target/site-map/comparing)
- [PortSwigger: Audit settings / insertion points](https://portswigger.net/burp/documentation/scanner/scan-configurations/audit-settings)
- [OWASP: API1 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP: API3 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)
- [OWASP: API5 Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP: Authorization Testing Automation](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html)
