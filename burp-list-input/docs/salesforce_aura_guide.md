# 猿でもわかる Salesforce / Experience Cloud / Aura 通信ガイド

対象は、許可を得たWebアプリケーションの認可診断です。ここでは、MyTools の Authorization Planning を読むために必要なSalesforce知識だけを、できるだけ平易に説明します。

## まず結論

Aura通信、Apex、オンプレAPIは同じものではありません。

```text
利用者のブラウザ
  |
  +-- Aura通信 (/s/sfsites/aura など)
  |     +-- Salesforce Aura Framework
  |           +-- 標準Controller または Apex
  |
  +-- 通常HTTP (/web11/.../Login など)
  |     +-- WAF / Load Balancer / Reverse Proxy
  |           +-- 対象システムのバックエンド、またはオンプレ処理
  |
  +-- 別Hostへの通信
        +-- 外部API、別バックエンド、SaaS等
```

同じ画面操作から、Aura通信と通常HTTPが連続して発生することは普通です。`/web11/...`がAura通信の近くにあっても、それだけでは「Apexが動いた」「外部サイトへ送った」「オンプレへ到達した」のいずれも確定しません。

## 用語

| 言葉 | かんたんな意味 | 認可診断での意味 |
| --- | --- | --- |
| Experience Cloud | Salesforceで作る顧客・会員向けWebサイトの土台。 | Guestや外部ユーザーごとのデータ・操作差を確認する。 |
| Aura | Salesforce画面を動かすJavaScriptフレームワーク。 | 1つのHTTP Packetに複数actionが入るため、actionごとに分けて見る。 |
| Apex | Salesforceのサーバー内で動くプログラム。 | sharing、CRUD、FLS、業務上の所有者確認を正しく行う必要がある。 |
| 標準Controller | Salesforceが提供する処理。 | 標準だから安全、カスタムだから危険、とは限らない。 |
| カスタムApex | 組織やパッケージが作ったApex処理。 | 独自の認可・外部連携・業務ロジックが入りやすい。 |
| オンプレ | 会社が管理する社内・自社データセンター等の基盤。 | URLのHostが同じでも、プロキシがPathでオンプレへ転送する場合がある。 |
| リバースプロキシ | URLの入口で、裏側の処理先へ振り分ける仕組み。 | ブラウザから見えるHostだけでは物理的な宛先は分からない。 |

## Auraリクエストの形

Auraは通常、フォーム形式のPOSTで送られます。値はURLエンコードされるため、Burpでは長い文字列に見えます。

```http
POST /s/sfsites/aura HTTP/1.1
Content-Type: application/x-www-form-urlencoded

message={...actions...}
&aura.context={...framework context...}
&aura.pageURI=/s/customer/home
&aura.token=...
```

実際のURLや値は環境ごとに異なります。上記は構造を示す例です。

### `message`

サーバーへ「何をしてほしいか」を渡す命令書です。通常はJSONをフォーム値としてエンコードしたものです。代表的には`actions`配列を持ちます。

```json
{
  "actions": [
    {
      "id": "123;a",
      "descriptor": "apex://CustomerController/ACTION$getCustomer",
      "callingDescriptor": "markup://c:customerPage",
      "params": { "customerId": "001..." }
    }
  ]
}
```

| 項目 | 意味 | 認可診断での見方 |
| --- | --- | --- |
| `id` | 同じHTTP通信内でactionを対応付ける番号。 | Responseの結果とactionを対応させる。認可用IDではない。 |
| `descriptor` | 呼び出したいController/actionの名前。 | `aura://`は標準系、`apex://`はApex系の手掛かり。由来であって安全性判定ではない。 |
| `callingDescriptor` | 呼び出し元画面・コンポーネントの手掛かり。 | どの画面機能から来たかを追う補助。サーバー認可の根拠ではない。 |
| `params` | actionに渡す引数。 | record ID、owner ID、tenant、金額、状態、Object/Field指定などの候補を確認する。 |

`params`の値を変えても、サーバーが正しく拒否するなら脆弱性ではありません。正規通信を比較元にして、許可された範囲で最小限の値だけを確認します。

### `aura.context`

Aura Frameworkが画面状態を理解するための文脈情報です。`fwuid`、mode、application descriptor、loaded componentなどのフレームワーク用情報が入ることがあります。内容は画面・状態・製品バージョンで変わります。

これは、App候補や画面文脈を把握する補助情報です。ここにある値だけで、利用者の権限、物理的宛先、データ所有者を断定してはいけません。

### `aura.pageURI`

Aura側が認識している、サイト内の現在ページ・仮想ページのURIです。たとえば`/s/customer/home`のような値です。

これは実際のHTTP送信先Pathと別のことがあります。`aura.pageURI`を`/web11/...`へ変えるだけで、オンプレの宛先が切り替わると考えてはいけません。画面遷移とAura actionを関連付ける補助情報として使います。

### `aura.token`

Auraリクエストを保護するためのフレームワーク用トークンです。画面や状態によって空・未設定に見える場合もあります。

通常、これは業務データでもApex method指定でもありません。認証Cookieや`Authorization`ヘッダーとも別に扱います。token値の有無・変化だけで認可可否を判断せず、元の正規通信を基に比較します。無作為な変更は単に通信を壊すことがあります。

## AuraとApexの関係

Aura通信だから必ずApex、ではありません。Apexが関係しているから必ずAura通信、でもありません。

| 形 | Apexとの関係 | 何を確認するか |
| --- | --- | --- |
| `aura://RecordUiController/ACTION$...` | Salesforce標準Controllerの可能性が高い。 | descriptor、Object/Field、Salesforce設定。 |
| `apex://CustomerController/ACTION$...` | Apex Controllerを呼ぶ手掛かり。 | class access、sharing、CRUD/FLS、業務認可。 |
| `ApexActionController`経由 | 汎用入口。paramsのclass名・method名から実体候補を追えることがある。 | Authorization PlanningのOrigin Reason、params。 |
| `/services/apexrest/...` | Apex RESTとしてApexが関係する可能性が高い。 | Path、Method、Apex REST実装、認証・共有。 |
| `/web11/.../Login`等の通常HTTP | Path名だけではApexとの関係は不明。 | 仕様書、LB/API Gateway、レスポンスヘッダー、実装。 |

## `/web11/...`は外部サイトか

先頭が`/`のPathは、ブラウザから見ると現在のHostへの通信です。別ドメインの外部サイトへ直接送ることを意味しません。

ただし、同じHostの入口でPathごとにオンプレへ転送する構成はあり得ます。したがって、ブラウザでの見え方と物理的な処理先は別です。

MyToolsの`Route Classification`では、通常HTTPを`Custom same-origin/backend route`や`External/cross-host route`として分類します。`On-prem`は通信から自動断定せず、仕様書に基づくDestination ruleに一致した場合だけ付ける利用者定義ラベルです。

```text
On-prem | ^portal\.example\.test$ | ^/web11/.+/(Login|Entry|Message)$
```

## 認可テストでの最小チェックリスト

1. Guest、一般ユーザーA、一般ユーザーBなど、比較する主体ごとの通信を集める。
2. Commentに`[group="user1"]`、`[group="user2"]`のようなGroupを付ける。
3. Aura action、通常HTTP endpoint、GraphQL operationを別々のOperationとして確認する。
4. `customerId`、`recordId`、`ownerId`、`tenant`、`amount`、`status`等の候補を確認する。
5. 本人所有、別ユーザー所有、別テナントなど、正しいテストデータ関係を先に定義する。
6. tokenやframework値を適当に作らず、正規通信を比較元にする。
7. HTTP 200だけで成功、403だけで安全と決めず、Response、状態変化、期待ポリシーを確認する。

## このガイドで断定しないこと

通信から分かるのは観測できた形と手掛かりまでです。Apexの共有モード、Object CRUD、FLS、Sharing Rule、Guest設定、オンプレ側の認可実装、実際の物理宛先は、Salesforce設定・コード・インフラ設定・仕様書との照合が必要です。
