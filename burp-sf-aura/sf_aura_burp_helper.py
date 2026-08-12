# -*- coding: utf-8 -*-
"""
sf_aura_burp_helper.py - Burp Suite Pro 拡張（Python 2 / Jython）

Salesforce(Aura/Experience Cloud) 診断を、Burpの HTTP history 上で直接支援するプラグイン。
python/burp_to_csv.py と同一のロジック（分類・Aura集約キー・ワード照合）を可能な限り
忠実に再実装し、両者の解析結果（No/AggKey/AggRole/Vuln-No）が一致するようにしている。

--------------------------------------------------------------------------------
機能
--------------------------------------------------------------------------------
① 採番      : HTTP history の各パケット Comment 欄先頭に固定番号 [0001] を記入。
              Save items(XML)出力後、burp_to_csv.py の No/Comment と対応付けできる。
② Aura集約  : 同一操作の繰り返し通信（フォーム逐次送信等）を代表/集約対象/単独で判別。
              一覧表示に加え、「集約対象」だけに予約色をオンデマンドで適用できる
              （ボタンを押した時だけ・ユーザー自身の色分けには一切自動介入しない）。
③ ワード照合: GUIでロードした3列CSV（wordlist1 / wordlist2 / Vuln-No）でパケット全要素
              （パス・クエリ・リクエストヘッダ・リクエストボディ・レスポンスヘッダ・
              レスポンスボディ）を照合し、選択中(カレント)パケットの専用タブに
              ヒットしたVuln-Noと「どこで見つかったか」を表示する。
              wordlist1・wordlist2 内は "/" 区切りで複数ワード（同一リスト内はOR固定）。
              [ルール]タブはリクエスト用／レスポンス用の上下2段に分かれており、
              wordlist1とwordlist2の結合条件（AND/OR）はそれぞれ独立してGUIで切り替える。
④ 非干渉    : 採番はCommentのみ、集約色は「予約色」のオンデマンド適用/クリアのみ
              （クリアも予約色のセルだけが対象。ユーザーが付けた他の色は変更しない）。
⑤ 比較容易化: 同一アルゴリズム・同一CSV形式のため、burp_to_csv.py の出力(packets.csv)と
              No/AggKey/AggRole/Vul-No を突き合わせやすい。解析結果のCSVエクスポートも可能。

--------------------------------------------------------------------------------
導入方法（概要。詳細は README.md 参照）
--------------------------------------------------------------------------------
1. Burp Suite Pro → Extender → Options → Python Environment に jython-standalone.jar を設定
2. Extender → Extensions → Add → Extension type: Python → 本ファイルを選択 → Next

--------------------------------------------------------------------------------
設計メモ（重要）
--------------------------------------------------------------------------------
本ファイルは、Burp(Jython/Python 2)上でも、素の Python 3 上でも「コアロジック部分」
だけは import 可能なように、Java/Burp 依存 import を try/except で分離している
（`ON_JYTHON` フラグ）。これにより、分類・集約キー・ワード照合のロジックを
python/burp_to_csv.py の実際の出力と突き合わせて検証できる
（scratchpad 上のパリティ検証スクリプトで実施）。

内部の分類コードは、Python 2 の str/unicode 比較の落とし穴を避けるため、
日本語ラベルではなく ASCII の内部コード（screen/spa/api/static）で保持し、
表示直前にのみ日本語ラベルへ変換する。
"""

import re
import json
import csv
import io
import hashlib

try:
    # Python 2 / Jython
    from urllib import unquote_plus
except ImportError:
    # Python 3（コアロジックのローカル検証用）
    from urllib.parse import unquote_plus

try:
    # Python 2 / Jython
    from urllib import quote_plus
except ImportError:
    # Python 3（コアロジックのローカル検証用）
    from urllib.parse import quote_plus


# ================================================================================
# Burp / Swing 依存 import（Jython上でのみ成功する）
# ================================================================================
ON_JYTHON = True
try:
    from burp import (IBurpExtender, ITab, IMessageEditorTabFactory, IMessageEditorTab,
                       IContextMenuFactory)
    from javax.swing import (JPanel, JTable, JScrollPane, JButton, JLabel, JTextField,
                              JRadioButton, ButtonGroup, JTabbedPane, JTextArea, JComboBox,
                              JFileChooser, JOptionPane, BoxLayout, SwingUtilities,
                              JMenuItem, JSplitPane, JCheckBox, BorderFactory, Box,
                              ListSelectionModel)
    from javax.swing.table import DefaultTableModel
    from java.awt import BorderLayout, GridLayout, FlowLayout, Dimension, Font, Color, Toolkit
    from java.awt.datatransfer import StringSelection
    from java.io import File
    from java.util import Comparator
except ImportError:
    ON_JYTHON = False


# ================================================================================
# 定数（分類・Aura関連）
# ================================================================================

CLS_SCREEN = "screen"
CLS_SPA = "spa"
CLS_API = "api"
CLS_STATIC = "static"

# 表示ラベル（日本語）。内部ロジックでは使わず、GUI表示直前にのみ参照する。
CLS_LABELS = {
    CLS_SCREEN: u"画面",
    CLS_SPA: u"画面更新(SPA)",
    CLS_API: u"API",
    CLS_STATIC: u"静的",
}

AURA_PATH_MARKERS = ("/aura", "sfsites/aura", "auracmpdef", "auraresources")
STATIC_EXTS = set(["js", "css", "png", "jpg", "jpeg", "gif", "svg", "woff", "woff2",
                    "ico", "map", "ttf", "eot", "webp", "bmp"])
STATIC_MIME = ("script", "css", "image", "font")

OBJECT_NAME_KEYS = set(["objectapiname", "entitynameorid", "entityname", "apiname",
                         "objectname", "sobjecttype", "sobject", "objecttype", "entity"])

# --- Aura診断（能動送信）関連の定数 ---
# aura-inspector本家と同じ4パスを、エンドポイント自動検出とApp Path逆算の両方で使う。
AURA_ENDPOINT_PATH_CANDIDATES = (u"/s/sfsites/aura", u"/s/aura", u"/aura", u"/sfsites/aura")
AURA_DEFAULT_USER_AGENT = (u"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.16; rv:85.0) "
                            u"Gecko/210100101 Firefox/85.0")
# セッション/トークン切れの早期検知に使う、認証エラーらしき文言の部分一致リスト（小文字化して比較）。
AURA_AUTH_ERROR_MARKERS = (u"invalid session", u"unauthenticated", u"invalid_session_id",
                            u"session expired", u"invalidsessiontime")

# Burpで有効な highlight 色（IHttpRequestResponse.setHighlight）
BURP_HIGHLIGHT_COLORS = ["red", "orange", "yellow", "green", "cyan", "blue",
                          "pink", "magenta", "gray"]

# 解析対象の場所ラベル（表示用）。[ルール]タブはリクエスト用・レスポンス用に分かれており、
# それぞれ別のコーパス（LOCATION_ORDER / RESPONSE_LOCATION_ORDER）を照合する。
# このラベル辞書自体はどちらの照合結果の表示にも共通で使う（format_word_loc_pairs等）。
LOCATION_LABELS = {
    "path": u"パス",
    "query": u"クエリ",
    "reqHeaders": u"リクエストヘッダ",
    "reqBody": u"リクエストボディ",
    "respHeaders": u"レスポンスヘッダ",
    "respBody": u"レスポンスボディ",
}
LOCATION_ORDER = ["path", "query", "reqHeaders", "reqBody"]
RESPONSE_LOCATION_ORDER = ["respHeaders", "respBody"]


# ================================================================================
# コアロジック（python/burp_to_csv.py と可能な限り同一の挙動になるよう再実装）
# ここから下の関数群は Python 2 / Python 3 の両方で動作する（Java依存なし）。
# ================================================================================

def is_static(ext, resp_mime):
    if ext and ext.lower() in STATIC_EXTS:
        return True
    rm = (resp_mime or "").lower()
    for s in STATIC_MIME:
        if s in rm:
            return True
    return False


def classify(path, req_body_text, resp_mime, ext):
    """通信を分類し ASCII 内部コード(screen/spa/api/static)を返す。
    判定順序は burp_to_csv.py の classify() と同一。"""
    p = (path or "").lower()
    body = req_body_text or ""
    if "auraanalytic" in p:
        return CLS_API
    marker_hit = False
    for k in AURA_PATH_MARKERS:
        if k in p:
            marker_hit = True
            break
    if marker_hit or ("message=" in body) or ("aura.context=" in body):
        return CLS_SPA
    if is_static(ext, resp_mime):
        return CLS_STATIC
    if resp_mime and "html" in resp_mime.lower():
        return CLS_SCREEN
    return CLS_API


def short_descriptor(desc):
    """aura descriptor を短縮。aura://ApexActionController/ACTION$execute -> ApexActionController/execute"""
    if not desc:
        return ""
    d = desc.split("://", 1)[-1]
    if "/ACTION$" in d:
        left, act = d.split("/ACTION$", 1)
        ctrl = left.split(".")[-1].split("/")[-1]
        return "%s/%s" % (ctrl, act)
    return d.split(".")[-1]


def looks_like_lwc_apex_descriptor(short_desc):
    """短縮形descriptor（short_descriptor()の出力）が、LWC(Lightning Web Components)の
    imperative/wire Apex呼び出しで使われる汎用ディスパッチコントローラ（ApexActionController）の
    パターンに一致するか判定する。
    Aura Componentsのコントローラは通常 java://<Class>/ACTION$<method> の形でクラス名が
    descriptorに直接現れるが、LWCは呼び出し先クラス名をparams側に載せてこの汎用コントローラ
    (aura://ApexActionController/ACTION$execute)を呼ぶため、descriptorだけでは呼び出し元が
    LWCかAuraかを直接判別できない代わりに、このパターン自体がLWC由来である可能性のシグナルになる。
    あくまで推定であり断定はできない（動的にAuraから同じ経路を使うケースもあり得るため）。"""
    if not short_desc:
        return False
    return short_desc.startswith(u"ApexActionController/")


_NATURAL_SORT_SPLIT_RE = re.compile(r'(\d+)')


def natural_sort_key_parts(s):
    """自然順ソート用に文字列を数値チャンク(int)と非数値チャンク(unicode)に分割する。
    例: "SEC-10" -> [u"SEC-", 10, u""]。Vuln-No列（"1","3","10"等）を辞書順（1,10,3のように
    並んでしまう）ではなく、人間の直感通りの順序（1,3,10）でソートするために使う。
    数値でないVuln-No（"SEC-1"等）が混在していても、数値チャンクだけを数値として比較し、
    残りは文字列として比較するため破綻しない。"""
    if not s:
        return [u""]
    parts = _NATURAL_SORT_SPLIT_RE.split(s)
    return [int(p) if p.isdigit() else p for p in parts]


def _try_parse_json(s):
    if not isinstance(s, (str, type(u""))):
        return None
    t = s.strip()
    if len(t) == 0 or t[0] not in ("{", "["):
        return None
    try:
        parsed = json.loads(t)
    except Exception:
        return None
    if isinstance(parsed, (dict, list)):
        return parsed
    return None


_FLATTEN_CAP = 4000


def flatten(obj, prefix, out, depth=0, max_depth=8):
    """dict/list を再帰的にリーフのパスへ平坦化。out に (path, value) を追加。
    リーフ文字列がさらにJSON文字列（二重シリアライズ）なら同じpath配下に再帰展開する。
    python/burp_to_csv.py の flatten() と同一挙動。"""
    if len(out) > _FLATTEN_CAP:
        return
    if isinstance(obj, dict):
        if not obj:
            out.append((prefix, ""))
            return
        for k, v in obj.items():
            p = "%s.%s" % (prefix, k) if prefix else str(k)
            flatten(v, p, out, depth, max_depth)
    elif isinstance(obj, list):
        if not obj:
            out.append((prefix, ""))
            return
        for i, v in enumerate(obj):
            flatten(v, "%s[%d]" % (prefix, i), out, depth, max_depth)
    elif isinstance(obj, (str, type(u""))):
        out.append((prefix, obj))
        if depth < max_depth:
            parsed = _try_parse_json(obj)
            if parsed is not None:
                flatten(parsed, prefix, out, depth + 1, max_depth)
    else:
        out.append((prefix, obj))


def _parse_param_names(qs):
    """クエリ/フォーム文字列からパラメータ"名前"の一覧を返す（値のデコードはしない簡易版）。"""
    names = []
    if not qs:
        return names
    for pair in qs.split("&"):
        if not pair:
            continue
        k = pair.split("=", 1)[0]
        try:
            names.append(unquote_plus(k))
        except Exception:
            names.append(k)
    return names


def parse_aura_message_info(msg_json_text):
    """message(JSON文字列) を解析し、AggKey計算に必要な要約だけを返す。
    戻り値: {"descriptors": set([...]), "objects": set([...]), "apex": set([...])}

    "apex" は classname.method の集合。カスタムApex呼び出し(ApexActionController)は、
    どのクラス/メソッドを呼んでいても descriptor は常に同一になるため、
    対象オブジェクト名を持たない呼び出し同士を区別するために別途保持する
    （AggKeyの誤集約防止。python/burp_to_csv.py と同じ考え方）。"""
    info = {"descriptors": set(), "objects": set(), "apex": set()}
    try:
        data = json.loads(msg_json_text)
    except Exception:
        return info
    actions = data.get("actions") if isinstance(data, dict) else None
    if not isinstance(actions, list):
        return info
    for act in actions:
        if not isinstance(act, dict):
            continue
        desc = act.get("descriptor", "") or ""
        sd = short_descriptor(desc)
        if sd:
            info["descriptors"].add(sd)
        params = act.get("params", {})
        is_apex = "ApexActionController" in desc
        if is_apex and isinstance(params, dict):
            cls_name = params.get("classname") or params.get("apexClass") or ""
            method_name = params.get("method") or params.get("methodName") or ""
            apex_key = ("%s.%s" % (cls_name, method_name)).strip(".")
            if apex_key:
                info["apex"].add(apex_key)
        leaves = []
        flatten(params, "params", leaves)
        for path, val in leaves:
            if not isinstance(val, (str, type(u""))):
                continue
            leaf = path.rsplit(".", 1)[-1].split("[")[0].lower()
            if leaf in OBJECT_NAME_KEYS:
                if val and len(val) not in (15, 18):
                    info["objects"].add(val)
                elif val and not re.match(r'^[A-Za-z0-9]+$', val or ""):
                    info["objects"].add(val)
    return info


def looks_like_id(v):
    if not isinstance(v, (str, type(u""))):
        return False
    if len(v) not in (15, 18):
        return False
    return re.match(r'^[A-Za-z0-9]+$', v) is not None


def compute_agg_param_names(query, req_body_text, req_ctype):
    """API/非Aura通信・descriptorを持たないAura SPA通信の AggKey に使う
    「パラメータ名の集合」と「名前=値の集合」。
    python/burp_to_csv.py の extract_insertion_points() の
    looks_multipart/looks_form/looks_json/looks_xml 判定・優先順位を忠実に再現し、
    agg_param_names に集計される型（query/body-form/body-json/body-multipart）と
    集計されない型（aura/body-xml）を一致させる。
    戻り値: (names, pairs) の2-tuple。pairs は "名前=値" の集合で、
    descriptorを持たないAura SPA通信のAggKey（内容の違いまで識別する必要がある場合）に使う。"""
    names = set()
    pairs = set()

    def _add(n, v):
        names.add(n)
        pairs.add(u"%s=%s" % (n, v if v is not None else ""))

    for n in _parse_param_names(query):
        if n:
            # クエリは名前のみ扱う簡易パーサのため、値は元のqueryから改めて拾う
            names.add(n)
    if query:
        for pair in query.split("&"):
            if not pair:
                continue
            k, _, v = pair.partition("=")
            if not k:
                continue
            try:
                pairs.add(u"%s=%s" % (unquote_plus(k), unquote_plus(v)))
            except Exception:
                pairs.add(u"%s=%s" % (k, v))

    ct = (req_ctype or "").lower()
    body = req_body_text or ""

    looks_multipart = "multipart/form-data" in ct
    looks_form = ("urlencoded" in ct) or (
        (not ct) and ("=" in body) and (body[:2] != "{[") and (len(body) == 0 or body[0] not in ("{", "[")))
    looks_json = ("json" in ct) or (len(body) > 0 and body[0] in ("{", "["))
    looks_xml = ("xml" in ct) or (body.lstrip()[:5].lower().startswith("<?xml"))

    if looks_multipart:
        m = re.search(r"boundary=([^\s;]+)", req_ctype or "")
        boundary = m.group(1).strip('"') if m else ""
        if boundary:
            for part in body.split("--" + boundary):
                mm = re.search(r'name="([^"]+)"', part)
                if mm:
                    _add(mm.group(1), part.strip()[-80:])
    elif looks_form:
        for pair in body.split("&"):
            if not pair:
                continue
            k, _, v = pair.partition("=")
            if k in ("message", "aura.context", "aura.token", "aura.pageURI"):
                continue
            try:
                _add(unquote_plus(k), unquote_plus(v))
            except Exception:
                _add(k, v)
    elif looks_json:
        parsed = _try_parse_json(body)
        if parsed is not None:
            leaves = []
            flatten(parsed, "", leaves)
            for path, v in leaves:
                if path:
                    _add(path, v if isinstance(v, (str, type(u""))) else "")
    elif looks_xml:
        pass  # burp_to_csv でも body-xml は agg_param_names に集計されない

    return names, pairs


def compute_agg_key(cls_code, path, method, has_cookie, agg_param_names, descriptors, objects, pageuri,
                     apex=None, agg_param_pairs=None):
    """python/burp_to_csv.py の agg_key 計算と同一の分岐・書式。

    apex(classname.method の集合) を含める。カスタムApex呼び出しは、呼び出す
    クラス/メソッドが何であっても descriptor は常に同一（ApexActionController/execute）に
    なるため、descriptorだけをキーにすると、対象オブジェクト名を持たない別々のApex呼び出し
    （スカラー引数のみのメソッド等）が誤って同一グループに丸められる。これを防ぐため
    apex も集約キーに含めて区別する。

    cls_code==CLS_SPA だが descriptors が無い通信（例: auraCmpDef/auraResources等の
    コンポーネント定義取得）は、パラメータの「名前」だけでなく「値」まで含めてキーにする
    （agg_param_pairs）。これは、名前だけで揃えると、実際には別内容（別コンポーネント等）の
    取得なのに隣接していれば誤って同一グループに丸められてしまうため。"""
    if apex is None:
        apex = set()
    if agg_param_pairs is None:
        agg_param_pairs = set()
    authtag = "auth" if has_cookie else "guest"
    if cls_code == CLS_SPA and descriptors:
        objtag = ",".join(sorted(objects)) if objects else "-"
        apextag = ",".join(sorted(apex)) if apex else "-"
        return "AURA %s [%s] apex=%s obj=%s page=%s %s" % (
            path, ",".join(sorted(descriptors)), apextag, objtag, pageuri or "", authtag)
    elif cls_code == CLS_SPA:
        content_sig = ",".join(sorted(agg_param_pairs))
        if len(content_sig) > 300:
            content_sig = hashlib.sha1(content_sig.encode("utf-8")).hexdigest()
        return "AURASPA %s {%s} %s" % (path, content_sig, authtag)
    elif cls_code == CLS_API:
        return "%s %s {%s} %s" % (method, path, ",".join(sorted(agg_param_names)), authtag)
    else:
        return "%s %s" % (method, path)


def extract_aura_message_and_pageuri(req_body_text, req_ctype):
    """form-urlencodedボディから message/aura.pageURI を取り出す。
    戻り値: (aura_info dict, pageuri str)"""
    aura_info = {"descriptors": set(), "objects": set(), "apex": set()}
    pageuri = ""
    ct = (req_ctype or "").lower()
    body = req_body_text or ""
    looks_form = ("urlencoded" in ct) or (
        (not ct) and ("=" in body) and (len(body) == 0 or body[0] not in ("{", "[")))
    if not looks_form:
        return aura_info, pageuri
    for pair in body.split("&"):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        if k == "message":
            try:
                decoded = unquote_plus(v)
            except Exception:
                decoded = v
            aura_info = parse_aura_message_info(decoded)
        elif k == "aura.pageURI":
            try:
                pageuri = unquote_plus(v)
            except Exception:
                pageuri = v
    return aura_info, pageuri


def extract_aura_context_and_token(req_body_text, req_ctype):
    """form-urlencodedのAuraリクエストボディから aura.context / aura.token を取り出す。
    extract_aura_message_and_pageuri の姉妹関数（あちらは message/aura.pageURI 用）。
    「Aura診断」タブが、Proxy history上の実際に捕捉済みのAuraリクエストから
    その場で有効な context/token を再利用するために使う。
    戻り値: (aura_context_json_str, aura_token_str)。見つからなければ None。"""
    ct = (req_ctype or "").lower()
    body = req_body_text or ""
    looks_form = ("urlencoded" in ct) or (
        (not ct) and ("=" in body) and (len(body) == 0 or body[0] not in ("{", "[")))
    if not looks_form:
        return None, None
    aura_context = None
    aura_token = None
    for pair in body.split("&"):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        if k == "aura.context":
            try:
                aura_context = unquote_plus(v)
            except Exception:
                aura_context = v
        elif k == "aura.token":
            try:
                aura_token = unquote_plus(v)
            except Exception:
                aura_token = v
    return aura_context, aura_token


# --------------------------------------------------------------------------------
# Aura診断（能動送信）: リクエスト構築・応答パースの純粋ロジック
# --------------------------------------------------------------------------------
# ここから下は Burp/Swing に依存しない文字列・dict・JSON操作のみで構成し、CPython3で
# 直接importしてユニットテストできるようにする（flatten_for_csv/build_corpus_lower等と
# 同じ設計方針）。実際にHTTPリクエストを送信する部分（callbacks.makeHttpRequest等）は
# 下の `if ON_JYTHON:` 内の BurpExtender._aura_send_actions に閉じ込める。
#
# 参考実装: Google/Mandiant aura-inspector (https://github.com/google/aura-inspector)
# の aura_helper.py にある各手法（AuraActionHelper/AuraHelper）を、Jython/Burp拡張の
# 制約に合わせて移植したもの。descriptor/paramsの形は本家と可能な限り一致させている。

def build_aura_action(action_id, descriptor, params=None, calling_descriptor=u"UNKNOWN"):
    return {
        "id": action_id,
        "descriptor": descriptor,
        "callingDescriptor": calling_descriptor,
        "params": params or {},
    }


def chunk_actions(actions, chunk_size=100):
    """actionsを最大chunk_size件ずつに分割する（Auraへの1リクエストあたりの
    バルクaction数を抑えるため。aura-inspector本家も100件単位で分割している）。"""
    chunk_size = max(1, chunk_size)
    return [actions[i:i + chunk_size] for i in range(0, len(actions), chunk_size)]


def build_aura_context_json(fwuid, app_name, mode=u"PROD", application_markup_key=None):
    key = application_markup_key or (u"APPLICATION@markup://%s" % app_name)
    return json.dumps({
        "mode": mode,
        "fwuid": fwuid,
        "app": app_name,
        "loaded": {key: app_name},
        "dn": [],
        "globals": {},
        "uad": False,
    })


def build_aura_message_json(actions):
    return json.dumps({"actions": actions})


def build_aura_post_body(message_json, aura_context_json, aura_token, page_uri=u"unknown"):
    """Auraエンドポイントへのform-urlencoded POSTボディを組み立てる。
    quote_plus はPython2/3いずれも unicode/str を渡せば内部でUTF-8エンコードするため、
    呼び出し側で個別にencode()する必要はない。"""
    parts = [
        u"message=" + quote_plus(message_json),
        u"aura.context=" + quote_plus(aura_context_json),
        u"aura.pageURI=" + quote_plus(page_uri or u"unknown"),
        u"aura.token=" + quote_plus(aura_token or u"undefined"),
    ]
    return u"&".join(parts)


def parse_aura_response_json(resp_body_text):
    """Auraの応答本文をJSONとしてパースする。Auraはエラー時に非JSON文字列
    （"Expected:.. Actual:.." 等）を返すことがあるため、失敗時は例外を投げず None を返す。"""
    if not resp_body_text:
        return None
    try:
        return json.loads(resp_body_text)
    except Exception:
        return None


def extract_action_responses_by_id(resp_json):
    """応答JSONの actions 配列を、action id をキーにした辞書に変換する。"""
    result = {}
    if not resp_json:
        return result
    for action in (resp_json.get("actions") or []):
        aid = action.get("id")
        if aid is not None:
            result[aid] = action
    return result


def action_state(action_resp):
    if not action_resp:
        return u""
    return action_resp.get("state", u"") or u""


def looks_like_valid_aura_endpoint_response(resp_text):
    """Auraエンドポイント自動検出の判定: 応答に "markup://" を含めば、そのパスが
    実際にAuraエンドポイントとして機能していると判断する（aura-inspector本家と同じ判定）。"""
    return bool(resp_text) and (u"markup://" in resp_text)


_AURA_TOKEN_RE = re.compile(r'eyJub[^";]+')


def parse_aura_token_from_text(text):
    """テキスト（HTMLページ本文やSet-Cookieヘッダー値）からAuraトークンらしき文字列を
    抜き出すベストエフォートの補助関数。コールドスタート時、エンドポイント自動検出の
    応答にたまたまトークンが含まれていた場合に自動入力の足しにする程度の位置づけで、
    通常は手動入力を前提とする（HTMLスクレイピングによる能動的な発見は本機能の対象外）。"""
    if not text:
        return None
    m = _AURA_TOKEN_RE.search(text)
    return m.group(0) if m else None


# --- 偵察アクション: aura-inspector本家の各手法に1:1対応させたビルダー/パーサー ---

def build_getconfigdata_action(action_id):
    return build_aura_action(action_id, u"aura://HostConfigController/ACTION$getConfigData")


def parse_getconfigdata_result(action_resp):
    """-> (apiNamesToKeyPrefixes: dict, cspTrustedSites: list)。失敗時は ({}, [])。"""
    if action_state(action_resp) != u"SUCCESS":
        return {}, []
    rv = action_resp.get("returnValue") or {}
    return (rv.get("apiNamesToKeyPrefixes") or {}), (rv.get("cspTrustedSites") or [])


def build_getitems_count_action(action_id, object_name):
    params = {
        "entityNameOrId": object_name,
        "layoutType": "COMPACT",
        "pageSize": 1,
        "currentPage": 1,
        "useTimeout": False,
        "getCount": True,
        "enableRowActions": False,
    }
    return build_aura_action(
        action_id,
        u"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider."
        u"SelectableListDataProviderController/ACTION$getItems",
        params)


def parse_getitems_count_result(action_resp):
    if action_state(action_resp) != u"SUCCESS":
        return None
    rv = action_resp.get("returnValue") or {}
    return rv.get("totalCount")


def build_listview_picker_action(action_id, object_name):
    params = {"scope": object_name, "maxMruResults": 10, "maxAllResults": 20}
    return build_aura_action(
        action_id,
        u"serviceComponent://ui.force.components.controllers.lists.listViewPickerDataProvider."
        u"ListViewPickerDataProviderController/ACTION$getInitialListViews",
        params)


def parse_listview_picker_result(action_resp):
    if action_state(action_resp) != u"SUCCESS":
        return []
    rv = action_resp.get("returnValue") or {}
    views = rv.get("listViews") or []
    return [v.get("name") for v in views if v.get("name")]


def build_listview_items_action(action_id, object_name, filter_name):
    params = {
        "filterName": filter_name,
        "entityName": object_name,
        "pageSize": 50,
        "layoutType": "LIST",
        "getCount": True,
        "enableRowActions": False,
        "offset": 0,
    }
    return build_aura_action(
        action_id,
        u"serviceComponent://ui.force.components.controllers.lists.listViewDataManager."
        u"ListViewDataManagerController/ACTION$getItems",
        params)


def parse_listview_items_result(action_resp):
    if action_state(action_resp) != u"SUCCESS":
        return False
    rv = action_resp.get("returnValue") or {}
    return len(rv.get("recordIdActionsList") or []) > 0


def build_home_bootstrap_action(action_id):
    return build_aura_action(
        action_id,
        u"serviceComponent://ui.communities.components.aura.components.communitySetup.cmc."
        u"CMCAppController/ACTION$getAppBootstrapData")


def parse_home_bootstrap_urls(raw_action_entry):
    """Home URL一覧を抜き出す。returnValueではなく、componentのmodelの中にある
    （aura-inspector本家実装通りの既知の癖。returnValueには入らない）。
    raw_action_entryは応答JSONのactions配列の該当要素そのもの
    （action_stateがSUCCESSであることは呼び出し側で確認しておくこと）。"""
    try:
        components = raw_action_entry.get("components") or []
        if not components:
            return {}
        model = components[0].get("model") or {}
        return model.get("apiNameToObjectHomeUrls") or {}
    except Exception:
        return {}


def build_selfreg_actions(id_enabled, id_url):
    return [
        build_aura_action(id_enabled,
                           u"apex://applauncher.LoginFormController/ACTION$getIsSelfRegistrationEnabled"),
        build_aura_action(id_url,
                           u"apex://applauncher.LoginFormController/ACTION$getSelfRegistrationUrl"),
    ]


def parse_selfreg_result(action_resp_enabled, action_resp_url):
    """-> (enabled: bool, signup_url: str or None)"""
    if action_state(action_resp_enabled) != u"SUCCESS":
        return False, None
    enabled = bool(action_resp_enabled.get("returnValue"))
    if not enabled:
        return False, None
    url = None
    if action_state(action_resp_url) == u"SUCCESS":
        url = action_resp_url.get("returnValue")
    return True, url


def build_graphql_availability_action(action_id):
    params = {
        "queryInput": {
            "operationName": "getUsersCount",
            "query": "query getUsersCount{uiapi{query{User{totalCount}}}}",
            "variables": {},
        }
    }
    return build_aura_action(action_id, u"aura://RecordUiController/ACTION$executeGraphQL", params)


def parse_graphql_availability_result(action_resp):
    if action_state(action_resp) != u"SUCCESS":
        return False
    rv = action_resp.get("returnValue") or {}
    errors = rv.get("errors") or []
    return len(errors) == 0


_APEX_CONTROLLER_RE = re.compile(r'apex://[a-zA-Z0-9_-]+/ACTION\$[a-zA-Z0-9_-]+')
_RESOURCE_SRC_RE = re.compile(r'src="([^"]*)"')
_AURACMPDEF_RE = re.compile(r'/auraCmdDef\?[^"\']+')


def parse_apex_controller_names(js_text):
    """フェッチしたJS/コンポーネント定義本文から、カスタムApexコントローラの
    参照（apex://Controller/ACTION$method）を抜き出す。通常のブラウジングでは
    呼ばれないコントローラも、コンポーネント定義には静的に含まれるため発見できる。"""
    if not js_text:
        return set()
    return set(_APEX_CONTROLLER_RE.findall(js_text))


def parse_resource_urls_from_html(html_text):
    """アプリのルートページHTMLから、JS/コンポーネント定義らしきリソースURLを抜き出す
    （parse_apex_controller_namesでのフェッチ対象を集めるための前段）。"""
    if not html_text:
        return []
    return _RESOURCE_SRC_RE.findall(html_text) + _AURACMPDEF_RE.findall(html_text)


# --- データ抽出: GraphQL優先・getItemsフォールバック（新規実装部分） ---
# aura-inspector公開版は件数(totalCount)取得までしか実装しておらず、実際のフィールド値の
# 取得は意図的に省かれている。本ツールは正規の認可された脆弱性診断案件でのみ使用される
# ため、Mandiantのブログ記事で解説されている手法に基づき、実データの抽出まで実装する。

_GRAPHQL_BANNED_FIELDS = set([u"CloneSourceId"])
_GRAPHQL_BANNED_TYPES = set([u"ADDRESS", u"ANYTYPE", u"COMPLEXVALUE"])


def build_graphql_fields_action(action_id, object_names):
    """対象オブジェクト群（最大100件/バッチ）のフィールド名・型をGraphQLで取得するaction。"""
    formatted = json.dumps(list(object_names), separators=(",", ":"))
    query = (u"query getFields{uiapi{objectInfos(apiNames:%s){ApiName,fields{ApiName,dataType}}}}"
             % formatted)
    params = {"queryInput": {"operationName": "getFields", "query": query, "variables": {}}}
    return build_aura_action(action_id, u"aura://RecordUiController/ACTION$executeGraphQL", params)


def parse_graphql_fields_response(action_resp):
    """-> {object_api_name: [field_api_name, ...]}。
    ADDRESS/ANYTYPE/COMPLEXVALUE型と CloneSourceId フィールドは、後続のレコード抽出処理
    （行データのvalue取得）が正しく扱えないため除外する（既知の制約）。"""
    if action_state(action_resp) != u"SUCCESS":
        return {}
    rv = action_resp.get("returnValue") or {}
    try:
        object_infos = rv["data"]["uiapi"]["objectInfos"]
    except Exception:
        return {}
    result = {}
    for info in (object_infos or []):
        if not info:
            continue
        api_name = info.get("ApiName")
        if not api_name:
            continue
        fields = []
        for f in (info.get("fields") or []):
            if f.get("dataType") in _GRAPHQL_BANNED_TYPES:
                continue
            if f.get("ApiName") in _GRAPHQL_BANNED_FIELDS:
                continue
            if f.get("ApiName"):
                fields.append(f["ApiName"])
        result[api_name] = fields
    return result


def build_graphql_rows_action(action_id, object_name, field_names, page_size=2000, after_cursor=None):
    """指定オブジェクトの実レコード（フィールド値まで含む）をGraphQLで取得するaction。
    2,000件のgetItems上限を回避できる（Mandiantブログ記事で解説されている手法）。
    after_cursorを指定すると、その続きのページを取得する（pageInfo.endCursorをそのまま渡す）。"""
    field_selection = u",".join(u"%s{value}" % f for f in field_names)
    if after_cursor:
        args = u"first:%d, after:\"%s\"" % (page_size, after_cursor)
    else:
        args = u"first:%d" % page_size
    query = (u"query getRows{uiapi{query{%s(%s){edges{node{%s}}totalCount"
             u"pageInfo{endCursor hasNextPage hasPreviousPage}}}}}"
             % (object_name, args, field_selection))
    params = {"queryInput": {"operationName": "getRows", "query": query, "variables": {}}}
    return build_aura_action(action_id, u"aura://RecordUiController/ACTION$executeGraphQL", params)


def parse_graphql_rows_response(action_resp, object_name, field_names):
    """-> (rows: list[dict], end_cursor: str|None, has_next_page: bool,
           total_count: int|None, errors: list)"""
    rv = action_resp.get("returnValue") if action_resp else None
    errors = (rv or {}).get("errors") or []
    if action_state(action_resp) != u"SUCCESS" or not rv:
        return [], None, False, None, errors
    try:
        query_result = rv["data"]["uiapi"]["query"][object_name]
    except Exception:
        return [], None, False, None, errors
    if not query_result:
        return [], None, False, None, errors
    rows = []
    for edge in (query_result.get("edges") or []):
        node = edge.get("node") or {}
        row = {}
        for f in field_names:
            field_data = node.get(f)
            row[f] = field_data.get("value") if isinstance(field_data, dict) else None
        rows.append(row)
    page_info = query_result.get("pageInfo") or {}
    return (rows, page_info.get("endCursor"), bool(page_info.get("hasNextPage")),
            query_result.get("totalCount"), errors)


def build_getitems_full_action(action_id, object_name, page_size, current_page, sort_by=None):
    """GraphQL不可時のフォールバック抽出。件数取得版(layoutType=COMPACT/getCount=True)と
    異なり layoutType=FULL で実際のレコードデータを取得する。sort_by（例: "Name"/"-Name"）は、
    2,000件のページ上限に達した際に別順序で再取得し、取りこぼしを減らすための引数
    （Mandiantブログ記事で解説されている手法。完全性を保証するものではない）。"""
    params = {
        "entityNameOrId": object_name,
        "layoutType": "FULL",
        "pageSize": page_size,
        "currentPage": current_page,
        "useTimeout": False,
        "getCount": False,
        "enableRowActions": False,
    }
    if sort_by:
        params["sortBy"] = sort_by
    return build_aura_action(
        action_id,
        u"serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider."
        u"SelectableListDataProviderController/ACTION$getItems",
        params)


def parse_getitems_records(action_resp):
    if action_state(action_resp) != u"SUCCESS":
        return []
    rv = action_resp.get("returnValue") or {}
    return rv.get("records") or []


# --------------------------------------------------------------------------------
# ワードリスト（word.csv互換）: 読み込み・マッチング
# --------------------------------------------------------------------------------

def decode_csv_bytes(raw_bytes):
    """CSVファイルの生バイト列を unicode にデコードする。
    UTF-8（BOM可）を優先し、デコードに失敗した場合のみ cp932（Windows日本語環境の
    Excel等が書き出す一般的なエンコーディング）にフォールバックする。
    python/burp_to_csv.py の XML エンコーディング自動判定と同じ方針
    （成功したエンコーディングをそのまま信用し、スコアリング等の複雑な判定はしない）。
    日本語の comment 列等が生バイトのまま扱われると、UTF-8の各バイトが1文字ずつ
    Latin-1として解釈されたような文字化け（例: "に" → "ã«"）になるため、
    ファイル読み込み時点で必ずこのデコードを通す。
    戻り値: (decoded_text, encoding_label)"""
    try:
        return raw_bytes.decode("utf-8-sig"), u"UTF-8"
    except UnicodeDecodeError:
        pass
    try:
        return raw_bytes.decode("cp932"), u"cp932 (Shift_JIS系)"
    except UnicodeDecodeError:
        return raw_bytes.decode("utf-8-sig", "replace"), u"UTF-8(一部デコードできない文字がありました)"


def build_rules_from_rows(rows):
    """CSVの行データ（list of list）から (rules, mapping_desc) を返す。
    - ヘッダ行があり、いずれかの列名に "vul" を含む列があれば、それを Vuln-No 列とみなし、
      さらに列名に "comment" を含む列があれば、それを comment 列とみなす。
      残りの列のうち左から2列を list1, list2 とする（既存 word.csv: Vul-No,Method,param 互換）。
    - ヘッダが検出できない場合は、ユーザー仕様どおり位置指定:
      col0=list1, col1=list2, col2=Vuln-No, col3=comment（あれば）。
    rules の各要素: {"vuln_no": str, "list1": [str,...], "list2": [str,...], "comment": str}
    comment 列が無いCSVでも読み込めるよう、無ければ空文字列になる（後方互換）。
    """
    if not rows:
        return [], u"空のCSVです"

    header = rows[0]
    header_lower = [(c or "").strip().lower() for c in header]
    vuln_idx = None
    comment_idx = None
    for i, h in enumerate(header_lower):
        if "vul" in h and vuln_idx is None:
            vuln_idx = i
        elif "comment" in h and comment_idx is None:
            comment_idx = i

    if vuln_idx is not None:
        other_idx = sorted([i for i in range(len(header)) if i != vuln_idx and i != comment_idx])
        if len(other_idx) < 2:
            return [], u"ヘッダは検出されましたが列数が不足しています（Vuln-No以外に2列必要）"
        list1_idx, list2_idx = other_idx[0], other_idx[1]
        data_rows = rows[1:]
        mapping_desc = (u"ヘッダを検出: 列%d=Vuln-No, 列%d=wordlist1(%s), 列%d=wordlist2(%s)"
                         % (vuln_idx, list1_idx, header[list1_idx], list2_idx, header[list2_idx]))
        if comment_idx is not None:
            mapping_desc += u", 列%d=comment(%s)" % (comment_idx, header[comment_idx])
    else:
        list1_idx, list2_idx, vuln_idx, comment_idx = 0, 1, 2, 3
        data_rows = rows
        mapping_desc = (u"ヘッダなし: 列0=wordlist1, 列1=wordlist2, 列2=Vuln-No, "
                         u"列3=comment(あれば) として読み込みました")

    rules = []
    need = max(vuln_idx, list1_idx, list2_idx)
    for r in data_rows:
        if len(r) <= need:
            continue
        vuln_no = (r[vuln_idx] or "").strip()
        l1 = [w.strip() for w in (r[list1_idx] or "").split("/") if w.strip()]
        l2 = [w.strip() for w in (r[list2_idx] or "").split("/") if w.strip()]
        comment = ""
        if comment_idx is not None and len(r) > comment_idx:
            comment = (r[comment_idx] or "").strip()
        if not vuln_no or (not l1 and not l2):
            continue
        rules.append({"vuln_no": vuln_no, "list1": l1, "list2": l2, "comment": comment})
    return rules, mapping_desc


def _is_wildcard_list(words):
    """ワードリストに '*'（ワイルドカード）が含まれるか。
    同一リスト内は常にOR判定のため、'*' が1つでも含まれていれば、
    他の語の有無に関わらずそのリストは無条件に条件成立とみなす。"""
    return any((w or "").strip() == "*" for w in words)


def _any_hit(words, corpus, location_order=None):
    """words（各語。'*' は対象外）のいずれかが corpus内のいずれかの場所にヒットするか。
    '*' は実際にコーパス中の文字列として探すものではない（ワイルドカードの意味を持つため
    _is_wildcard_list 側で別途扱う）ので、ここではスキップする。
    location_order: 走査する場所（コーパスのキー）の順序リスト。省略時はリクエスト側の
    既定 LOCATION_ORDER を使う（後方互換）。レスポンス側を照合する場合は呼び出し側で
    RESPONSE_LOCATION_ORDER を明示的に渡す。
    戻り値: [(word, location), ...]（ヒットした語と場所の一覧。空なら不一致）"""
    order = location_order if location_order is not None else LOCATION_ORDER
    hits = []
    for w in words:
        wl = (w or "").strip()
        if not wl or wl == "*":
            continue
        wl_lower = wl.lower()
        for loc in order:
            text = corpus.get(loc, "")
            if text and wl_lower in text:
                hits.append((w, loc))
    return hits


def match_rules(rules, corpus, and_or_mode, location_order=None):
    """rules を corpus に対して照合する。
    corpus: リクエスト側なら {"path":lowertext, "query":..., "reqHeaders":..., "reqBody":...}
    （build_corpus_lower）、レスポンス側なら {"respHeaders":..., "respBody":...}
    （build_response_corpus_lower）。いずれも小文字化済みを渡すこと。
    and_or_mode: "AND" または "OR"
    location_order: corpus内をどのキー順で走査するか（_any_hit参照）。省略時はリクエスト側。
    レスポンス側を照合する場合は RESPONSE_LOCATION_ORDER を渡す。

    wordlist1/wordlist2 のいずれかに '*'（ワイルドカード）が含まれる場合、そのリストは
    常に条件成立とみなす（例: wordlist1="*", wordlist2="isAdmin" なら、isAdminの一致だけで
    ヒット判定したい、という使い方のため）。
    ただし、ワイルドカードを含むルールを and_or_mode="OR" のまま素直に評価すると、
    ワイルドカード側が常に真になり、もう一方の条件をまったく見ずに常にヒットしてしまう
    （意図しない緩さ）。これを避けるため、**ワイルドカードが絡むルールは and_or_mode の
    設定に関わらず常にAND相当**で判定する（＝ワイルドカードでない側の実際の一致結果だけで
    決まる）。and_or_mode を素直に使う場合と比べて判定方式が逆転するため、これを
    「結合条件を反転する」という形で実現している。
    戻り値: [(vuln_no, hits), ...]  hits = [(word, "list1"/"list2", location), ...]
    """
    results = []
    for rule in rules:
        wc1 = _is_wildcard_list(rule["list1"])
        wc2 = _is_wildcard_list(rule["list2"])
        h1 = _any_hit(rule["list1"], corpus, location_order)
        h2 = _any_hit(rule["list2"], corpus, location_order)
        m1 = wc1 or bool(h1)
        m2 = wc2 or bool(h2)
        if wc1 or wc2:
            ok = m1 and m2
        elif and_or_mode == "OR":
            ok = m1 or m2
        else:
            ok = m1 and m2
        if not ok:
            continue
        hits = [(w, "list1", loc) for (w, loc) in h1] + [(w, "list2", loc) for (w, loc) in h2]
        results.append((rule["vuln_no"], hits))
    return results


def format_word_loc_pairs(hits):
    """(word, list_name, location) のリストから、重複を除いた "word@location" のリストを返す
    （出現順を保持）。Commentマーカーの Vuln= 部分と、解析タブのワード照合一覧の両方から
    共通で使い、表示の食い違いが起きないようにする。"""
    seen = set()
    out = []
    for (w, _l, loc) in hits:
        key = (w, loc)
        if key not in seen:
            seen.add(key)
            out.append(u"%s@%s" % (w, loc))
    return out
    return results


def build_corpus_lower(path, query, req_headers_text, req_body_text):
    """[ルール]タブの**リクエスト用**ルール向けの照合コーパス。レスポンス用ルールは
    build_response_corpus_lower()が別に担当する。
    reqBody は URLデコードしてから格納する（Auraの message= はURLエンコードされたJSONのため、
    デコードしないと "://" 等の記号を含むワードが一致しない。python/burp_to_csv.py の
    recon scan_text と同じ考え方）。"""
    try:
        decoded_body = unquote_plus(req_body_text) if req_body_text else ""
    except Exception:
        decoded_body = req_body_text or ""
    return {
        "path": (path or "").lower(),
        "query": (query or "").lower(),
        "reqHeaders": (req_headers_text or "").lower(),
        "reqBody": decoded_body.lower(),
    }


def build_response_corpus_lower(resp_headers_text, resp_body_text):
    """[ルール]タブの**レスポンス用**ルール向けの照合コーパス。build_corpus_lower()の
    レスポンス版。reqBodyと異なり unquote_plus によるURLデコードは行わない
    （レスポンス本文はHTML/JSON等が主で、URLエンコードされている前提が無く、誤デコードで
    本来の "+" 等の文字を壊すリスクがあるため）。"""
    return {
        "respHeaders": (resp_headers_text or "").lower(),
        "respBody": (resp_body_text or "").lower(),
    }


def merge_vuln_hits(*hit_lists):
    """複数のmatch_rules()結果（[(vuln_no,hits),...]のリスト）を、同じVuln-Noごとに
    hitsを結合して1つにまとめる。[ルール]タブのリクエスト用・レスポンス用の両方に同じ
    Vuln-Noが定義されていた場合、[解析]タブ・Commentマーカー上では1件のVuln-Noとして
    両方のヒット箇所（request/response双方のlocation）をまとめて表示するため。
    出現順は最初に登場した順を保つ。"""
    order = []
    merged = {}
    for hit_list in hit_lists:
        for vuln_no, hits in hit_list:
            if vuln_no not in merged:
                merged[vuln_no] = []
                order.append(vuln_no)
            merged[vuln_no].extend(hits)
    return [(vn, merged[vn]) for vn in order]


def hit_scope_label(vuln_no, request_vuln_nos, response_vuln_nos):
    """あるパケット内で、指定したVuln-Noがリクエスト用ルール／レスポンス用ルールの
    どちらでヒットしたかを表示用ラベルにする。
    request_vuln_nos/response_vuln_nos は、そのパケットの vuln_hits_request/
    vuln_hits_response（マージ前）から作った vuln_no の set。両方に含まれていれば
    （同じVuln-Noを両方の表に定義していて、かつ両方でヒットした場合）両方を表示する。"""
    in_req = vuln_no in request_vuln_nos
    in_resp = vuln_no in response_vuln_nos
    if in_req and in_resp:
        return u"リクエスト+レスポンス"
    if in_req:
        return u"リクエスト"
    if in_resp:
        return u"レスポンス"
    return u""


def flatten_for_csv(text, max_len=500):
    """Excelのセルに収まる長さへ整形する。改行はスペースに置換し、max_len超過分は
    切り詰めて "<---snip--->" マーカーと元の全文字数を付記する（省略されたことが
    一見してわかるようにするため）。"""
    if not text:
        return u""
    flat = text.replace(u"\r\n", u" ").replace(u"\n", u" ").replace(u"\r", u" ")
    if len(flat) <= max_len:
        return flat
    return u"%s <---snip---> (全%d文字)" % (flat[:max_len], len(flat))


# ================================================================================
# ここから Jython / Burp 依存部分（GUI・拡張本体）
# ================================================================================

if ON_JYTHON:

    NUMBER_PREFIX_DEFAULT = ""
    NUMBER_DIGITS_DEFAULT = 4

    def guess_ext(path):
        p = (path or "").rsplit("?", 1)[0]
        if "." not in p.rsplit("/", 1)[-1]:
            return ""
        tail = p.rsplit(".", 1)[-1]
        if 1 <= len(tail) <= 6 and re.match(r'^[A-Za-z0-9]+$', tail):
            return tail.lower()
        return ""

    def numbering_token(prefix, digits, number):
        try:
            fmt = "[%s%0" + str(int(digits)) + "d] "
            return fmt % (prefix, int(number))
        except Exception:
            return "[%s%d] " % (prefix, number)

    def numbering_regex(prefix):
        return re.compile(r'^\[' + re.escape(prefix) + r'\d+\]\s*')

    def safe_text(v):
        """JTableのセル値（Java Stringに由来するunicodeを含む）を、UnicodeEncodeErrorを
        起こさずにテキストとして扱えるようにする。
        Python 2では str(unicode_obj) が暗黙にASCIIへエンコードしようとするため、
        日本語等の非ASCII文字を含むセル（wordlist/Vuln-No/comment等）に対して呼ぶと
        "UnicodeEncodeError: 'ascii' codec can't encode characters ..." で例外になる。
        常に unicode を返すことでこれを避ける。"""
        if v is None:
            return u""
        if isinstance(v, unicode):
            return v
        try:
            return unicode(v)
        except Exception:
            try:
                return unicode(str(v), "utf-8", "replace")
            except Exception:
                return u""

    _BRACKET_SPAN_RE = re.compile(r'\[[^\[\]]*\]')

    def strip_all_brackets(text):
        """Comment内の [ ... ] で囲まれた部分をすべて取り除く（「追加コメント全クリア」用）。
        本ツールは採番トークン([0005])を先頭に、解析マーカー([SF Agg=...→代表[0005]]の
        ように入れ子になることがある)を末尾に書くため、単純な1回の正規表現置換では
        入れ子の内側しか消えず外側の角括弧が残ってしまう。そこで、角括弧が無くなるまで
        繰り返し除去することで、入れ子の深さに関わらず確実にすべて取り除く。
        （ユーザーが手動で入れた [ ] 形式のメモも区別なく削除される点に注意）"""
        cur = text or ""
        for _ in range(20):  # 異常な入力でも無限ループしないための安全策
            nxt = _BRACKET_SPAN_RE.sub("", cur)
            if nxt == cur:
                break
            cur = nxt
        return re.sub(r'\s+', ' ', cur).strip()

    # Comment末尾に書き込む「解析結果」マーカーの検出用正規表現。
    # 書き込み時は、まず既存のマーカー（前回実行分。旧版の [Vuln: ...] 形式も含む）を
    # 除去してから新しいマーカーを付け直すため、何度実行しても重複追記されない（冪等）。
    # 複数Vuln-Noヒット時、マーカー内部に改行を含めることがあるため、
    # re.DOTALL で "." が改行にもマッチするようにしている（付けないと、マーカーの
    # 途中に改行がある場合に検出・除去できず、実行するたびに重複追記されてしまう）。
    SF_MARKER_RE = re.compile(r'\s*\[(?:SF |Vuln:).*\]\s*$', re.DOTALL)

    # Comment先頭にある採番トークン（①採番機能が書く "[0005] " 等）を抜き出す正規表現。
    # 末尾が数字で終わる角括弧のみにマッチさせ、本機能自身が書く末尾の [SF ...] マーカー
    # （末尾が ")" 等で終わる）と誤って混同しないようにしている。
    LEADING_NUMBER_RE = re.compile(r'^\[([^\]]*\d)\]')

    def extract_leading_number(comment):
        """Comment先頭の採番トークンの中身（例 "0005"）を返す。無ければ None。"""
        m = LEADING_NUMBER_RE.match(comment or "")
        return m.group(1) if m else None

    def format_sf_marker(agg_role, agg_group_size, vuln_hits, rep_comment=None, cls_code=None,
                          comment_by_vuln=None):
        """分類(Cls)・集約判定(AggRole)・ワード照合ヒットを、Comment末尾に追記する短い文字列にする。
        例（ヒット1件でも複数件でも同じ書き方＝"Vuln(N件):" ヘッダ＋1件ずつ改行＋「・」）:
        "[SF Cls=画面更新(SPA) Agg=集約対象(size=3)→代表[0005] Vuln(1件):
        ・V-001(customerNumber@reqBody,QrCode@path)[要手動確認]]"
        Cls部分は cls_code が渡された場合のみ書く（CLS_LABELS を使い、burp_to_csv.py の
        「分類」列と同じ表記＝画面／画面更新(SPA)／API／静的にする。表記を独自に変えると
        packets.csv の分類列と見比べる際に紐づけにくくなるため、既存表記に統一している）。
        vuln_hits が空でも Agg 部分は常に書く（「集約対象か否か」を必ずComment上で
        判別できるようにするため）。
        Vuln部分は、見つかったVuln-Noごとに「実際にヒットした単語@ロケーション（例:reqBody）」を
        すべて列挙する（ロケーションだけでなく、どの単語が一致したのかを追えるようにするため）。
        ヒット件数が1件でも複数件でも書き方を統一している（別形式にすると、複数件ヒットした
        パケットとの見た目の違いに気付きにくいため）。
        comment_by_vuln（{vuln_no: comment}の辞書）を渡すと、該当するVuln-Noの直後に
        word.csvのcomment列の内容を `[...]` で追記する（無ければ何も付けない）。
        agg_role が「集約対象」の場合、rep_comment（代表パケットの現在のComment）から
        採番済みの番号（①採番機能が書いた [0005] 等）を抜き出し、
        「どの代表に集約されたか」を番号で参照できるようにする。
        代表がまだ採番されていない場合は "(未採番)" と表示する（先に①採番の実行を推奨）。"""
        parts = []
        if cls_code is not None:
            parts.append(u"Cls=%s" % CLS_LABELS.get(cls_code, cls_code))
        if agg_role == u"単独":
            agg_part = u"単独"
        elif agg_role == u"集約対象":
            rep_num = extract_leading_number(rep_comment) if rep_comment else None
            if rep_num:
                agg_part = u"集約対象(size=%d)→代表[%s]" % (agg_group_size, rep_num)
            else:
                agg_part = u"集約対象(size=%d)→代表(未採番)" % agg_group_size
        else:  # 代表
            agg_part = u"%s(size=%d)" % (agg_role, agg_group_size)
        parts.append(u"Agg=%s" % agg_part)
        if vuln_hits:
            vparts = []
            for vuln_no, hits in vuln_hits:
                wl_list = format_word_loc_pairs(hits)
                vpart = u"%s(%s)" % (vuln_no, ",".join(wl_list))
                rule_comment = comment_by_vuln.get(vuln_no, u"") if comment_by_vuln else u""
                if rule_comment:
                    vpart += u"[%s]" % rule_comment
                vparts.append(vpart)
            # ヒット件数が1件でも複数件でも書き方を統一する（1件だけ "Vuln=..." という
            # 別形式にすると、複数件ヒットしたパケットとの見た目の違いに気付きにくいため）。
            # 1件ずつ改行し、行頭に「・」を付けて見た目でも区切りがわかるようにする。
            parts.append(u"Vuln(%d件):\n%s"
                          % (len(vparts), u"\n".join(u"・%s" % v for v in vparts)))
        return u"[SF %s]" % " ".join(parts)

    class PacketInfo(object):
        """1パケット分の解析結果を保持する軽量コンテナ。"""
        def __init__(self):
            self.no = 0
            self.comment = ""
            self.method = ""
            self.path = ""
            self.query = ""
            self.host = ""
            self.url = ""
            self.cls_code = CLS_API
            self.has_cookie = False
            self.corpus = {}       # リクエスト用ルールの照合コーパス
            self.resp_corpus = {}  # レスポンス用ルールの照合コーパス
            self.descriptors = set()
            self.objects = set()
            self.apex = set()
            self.agg_key = ""
            self.agg_role = u"単独"
            self.agg_group_size = 1
            self.agg_rep_no = 0
            self.agg_rep_pkt = None  # 代表パケットの PacketInfo（自分自身が代表/単独なら None）
            self.vuln_hits = []            # [(vuln_no, hits), ...]（リクエスト+レスポンス統合後）
            self.vuln_hits_request = []    # 統合前のリクエスト用ルールのヒット（集計用に一時保持）
            self.vuln_hits_response = []   # 統合前のレスポンス用ルールのヒット
            self.identity = None  # (host, port, protocol, request_str)


    def analyze_http_item(helpers, http_service, request_bytes, response_bytes, comment=""):
        """1件の IHttpRequestResponse 相当データから PacketInfo を構築する。
        comment は呼び出し側で item.getComment() 等から取得して渡す
        （IMessageEditorController 経由では取得できないため、この関数の外側で扱う）。"""
        pkt = PacketInfo()
        pkt.comment = comment or ""
        try:
            req_info = helpers.analyzeRequest(http_service, request_bytes)
        except Exception:
            req_info = helpers.analyzeRequest(request_bytes)

        url = req_info.getUrl()
        pkt.path = url.getPath() or ""
        pkt.query = url.getQuery() or ""
        pkt.method = req_info.getMethod() or ""
        pkt.url = url.toString() if url is not None else ""

        req_headers = list(req_info.getHeaders())
        pkt.has_cookie = any(h.lower().startswith("cookie:") for h in req_headers)
        req_ctype = ""
        for h in req_headers:
            if h.lower().startswith("content-type:"):
                req_ctype = h.split(":", 1)[1].strip()
                break
        req_headers_text = "\n".join(req_headers)

        req_body_offset = req_info.getBodyOffset()
        req_body_bytes = request_bytes[req_body_offset:] if request_bytes is not None else bytearray()
        req_body_text = helpers.bytesToString(req_body_bytes) if req_body_bytes is not None else ""

        # レスポンスは分類（静的/画面 判定用の mimetype）に使うほか、[ルール]タブの
        # レスポンス用ルール照合コーパス（pkt.resp_corpus）もここで組み立てる。
        resp_mime = ""
        resp_headers_text = ""
        resp_body_text = ""
        if response_bytes is not None:
            try:
                resp_info = helpers.analyzeResponse(response_bytes)
                resp_mime = resp_info.getInferredMimeType() or resp_info.getStatedMimeType() or ""
                resp_headers_text = "\n".join(list(resp_info.getHeaders()))
                resp_body_offset = resp_info.getBodyOffset()
                resp_body_bytes = response_bytes[resp_body_offset:]
                resp_body_text = helpers.bytesToString(resp_body_bytes) if resp_body_bytes is not None else ""
            except Exception:
                pass

        ext = guess_ext(pkt.path)
        pkt.cls_code = classify(pkt.path, req_body_text, resp_mime, ext)

        aura_info, pageuri = extract_aura_message_and_pageuri(req_body_text, req_ctype)
        pkt.descriptors = aura_info["descriptors"]
        pkt.objects = aura_info["objects"]
        pkt.apex = aura_info["apex"]

        agg_names, agg_pairs = compute_agg_param_names(pkt.query, req_body_text, req_ctype)
        pkt.agg_key = compute_agg_key(pkt.cls_code, pkt.path, pkt.method, pkt.has_cookie,
                                       agg_names, pkt.descriptors, pkt.objects, pageuri, pkt.apex,
                                       agg_pairs)

        pkt.corpus = build_corpus_lower(pkt.path, pkt.query, req_headers_text, req_body_text)
        pkt.resp_corpus = build_response_corpus_lower(resp_headers_text, resp_body_text)

        try:
            host = http_service.getHost() if http_service else ""
            port = http_service.getPort() if http_service else 0
            proto = http_service.getProtocol() if http_service else ""
        except Exception:
            host, port, proto = "", 0, ""
        pkt.host = host
        req_str_key = helpers.bytesToString(request_bytes) if request_bytes is not None else ""
        pkt.identity = (host, port, proto, req_str_key)

        return pkt


    def quick_relevant(helpers, content_bytes, rule_words):
        """isEnabled用の軽量チェック。content(片側のみ)にAuraらしさ or ルール語が含まれるか。"""
        if content_bytes is None:
            return False
        try:
            text = helpers.bytesToString(content_bytes).lower()
        except Exception:
            return False
        for marker in AURA_PATH_MARKERS:
            if marker in text:
                return True
        if "message=" in text or "aura.context=" in text:
            return True
        for w in rule_words:
            if w and w.lower() in text:
                return True
        return False


    class _NoneLastIntComparator(Comparator):
        """件数列のソート用。None（未取得）は常に末尾に来るようにし、値がある場合は数値として
        比較する（DefaultTableModelは列の型を区別しないため、そのままだと文字列としての
        辞書順ソートになってしまう＝2桁以上の件数で意図しない順序になるのを防ぐ）。"""
        def compare(self, a, b):
            if a is None and b is None:
                return 0
            if a is None:
                return 1
            if b is None:
                return -1
            return int(a) - int(b)

    class _NaturalOrderComparator(Comparator):
        """Vuln-No列などの自然順ソート用。natural_sort_key_parts()で文字列を数値/非数値の
        チャンクに分割し、先頭から順に比較する。分割は非数値チャンクが必ず偶数インデックス
        （常にunicode）、数値チャンクが必ず奇数インデックス（常にint）になる設計のため、
        同じインデックス同士は常に同じ型になり、型変換なしで直接比較できる。
        これにより "1","3","10" が辞書順(1,10,3)ではなく数値としての直感的な順序(1,3,10)
        でソートされる。"""
        def compare(self, a, b):
            sa = safe_text(a) if a is not None else u""
            sb = safe_text(b) if b is not None else u""
            pa = natural_sort_key_parts(sa)
            pb = natural_sort_key_parts(sb)
            for x, y in zip(pa, pb):
                if x != y:
                    return -1 if x < y else 1
            if len(pa) != len(pb):
                return -1 if len(pa) < len(pb) else 1
            return 0

    # ----------------------------------------------------------------------------
    # メインの拡張クラス
    # ----------------------------------------------------------------------------

    class BurpExtender(IBurpExtender, ITab, IMessageEditorTabFactory, IContextMenuFactory):

        def registerExtenderCallbacks(self, callbacks):
            self._callbacks = callbacks
            self._helpers = callbacks.getHelpers()
            callbacks.setExtensionName("SF Aura Helper")

            self.rules_request = []
            self.rules_response = []
            self.rules_mapping_desc_request = u""
            self.rules_mapping_desc_response = u""
            self.and_or_mode_request = "AND"
            self.and_or_mode_response = "AND"
            self.reserved_color = "gray"

            self.index_by_identity = {}   # identity -> PacketInfo
            self.agg_groups = {}          # agg_key -> [PacketInfo,...] (No順)

            # Aura診断（能動送信）タブの状態。
            # dict: {"http_service", "host", "port", "protocol", "aura_endpoint_path",
            #        "app", "aura_context", "aura_token"}。未設定の間は None。
            self._aura_session = None
            self._aura_recon_result = {}  # データ抽出タブのオブジェクト選択元（偵察結果）

            self._build_gui()
            callbacks.addSuiteTab(self)
            callbacks.registerContextMenuFactory(self)
            self._log(u"拡張をロードしました。'コックピット' タブから操作できます。")

        # --- ITab ---
        def getTabCaption(self):
            return "SF Helper"

        def getUiComponent(self):
            return self.main_panel

        # ------------------------------------------------------------------------
        # GUI構築
        # ------------------------------------------------------------------------
        def _build_gui(self):
            self.main_panel = JPanel(BorderLayout())
            tabs = JTabbedPane()
            tabs.addTab(u"ルール", self._build_rules_panel())
            tabs.addTab(u"コックピット", self._build_cockpit_panel())
            tabs.addTab(u"解析", self._build_analysis_panel())
            tabs.addTab(u"採番", self._build_numbering_panel())
            tabs.addTab(u"集約色", self._build_color_panel())
            tabs.addTab(u"Aura診断", self._build_aura_audit_panel())
            self.main_panel.add(tabs, BorderLayout.CENTER)

            # ログ欄はコンソール風の配色（暗背景+明るい文字）にし、太字タイトル枠を付けて、
            # 上のタブ群（明るい配色）から視線が自然に集まるようにしている。
            self.log_area = JTextArea(7, 80)
            self.log_area.setEditable(False)
            self.log_area.setFont(Font("Monospaced", Font.BOLD, 12))
            self.log_area.setBackground(Color(24, 24, 24))
            self.log_area.setForeground(Color(120, 255, 140))
            self.log_area.setCaretColor(Color.WHITE)
            log_scroll = JScrollPane(self.log_area)
            log_scroll.setBorder(BorderFactory.createTitledBorder(u"実行ログ"))
            self.main_panel.add(log_scroll, BorderLayout.SOUTH)

        def _log(self, msg):
            def do_log():
                self.log_area.append(msg + "\n")
                self.log_area.setCaretPosition(self.log_area.getDocument().getLength())
            try:
                SwingUtilities.invokeLater(do_log)
            except Exception:
                pass

        # --- コックピットタブ ---
        def _build_cockpit_panel(self):
            """主要な操作を1画面に集約したダッシュボード。
            上段: Auto実行（採番→解析更新→Commentへ追記を一括実行。オプション2つを事前選択）。
            下段: 個別操作ボタン（既存の各タブの操作を、ボタンを押すだけで呼び出せるよう並べる。
            既存の各タブ自体（採番の接頭辞設定、集約色の色選択等）はそのまま残す）。
            区切りは JLabel の "■" 見出しではなく TitledBorder を使い、各行は明示的に
            LEFT_ALIGNMENT を設定する（BoxLayout.Y_AXIS の子要素はデフォルトで中央揃えになり、
            行ごとに幅が異なると左右がバラバラに見えるため）。"""
            outer = JPanel()
            outer.setLayout(BoxLayout(outer, BoxLayout.Y_AXIS))
            outer.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

            def left(component):
                component.setAlignmentX(0.0)
                return component

            # --- Auto実行 ---
            auto_box = JPanel()
            auto_box.setLayout(BoxLayout(auto_box, BoxLayout.Y_AXIS))
            auto_box.setBorder(BorderFactory.createTitledBorder(u"Auto実行（採番 → 解析更新 → Commentへ追記）"))
            left(auto_box)

            opt_row = left(JPanel(FlowLayout(FlowLayout.LEFT, 8, 4)))
            # 既定でどちらもON。「追加コメント全クリア」は元に戻せない操作のため、
            # ONのままAuto実行すると（_on_auto_run側で）確認ダイアログが必ず出る。
            self.auto_clear_brackets_chk = JCheckBox(u"実行前に「追加コメント全クリア」を行う", True)
            self.auto_apply_color_chk = JCheckBox(u"解析後に「集約対象へ予約色を適用」を行う", True)
            opt_row.add(self.auto_clear_brackets_chk)
            opt_row.add(self.auto_apply_color_chk)
            auto_box.add(opt_row)

            auto_btn_row = left(JPanel(FlowLayout(FlowLayout.LEFT, 8, 4)))
            btn_auto = JButton(u"▶ Auto実行", actionPerformed=self._on_auto_run)
            btn_auto.setFont(btn_auto.getFont().deriveFont(Font.BOLD))
            auto_btn_row.add(btn_auto)
            auto_box.add(auto_btn_row)

            auto_note = left(JTextArea(
                u"実行順序: (追加コメント全クリア ※チェック時のみ) → 採番 → 解析更新 →\n"
                u"(集約対象へ予約色を適用 ※チェック時のみ) → 解析結果をCommentへ追記\n"
                u"採番の接頭辞/桁数や集約色の色は、それぞれ [採番]/[集約色] タブの現在の設定を使います。\n"
                u"「追加コメント全クリア」は元に戻せません（チェックして実行すると確認ダイアログが出ます）。"))
            auto_note.setEditable(False)
            auto_note.setOpaque(False)
            auto_box.add(auto_note)

            outer.add(auto_box)
            outer.add(left(Box.createRigidArea(Dimension(0, 12))))

            # --- 個別操作 ---
            ind_box = JPanel(BorderLayout())
            ind_box.setBorder(BorderFactory.createTitledBorder(u"個別操作"))
            left(ind_box)

            grid = JPanel(GridLayout(0, 2, 12, 6))

            def add_op(label, desc, handler):
                grid.add(JButton(label, actionPerformed=handler))
                grid.add(JLabel(desc))

            add_op(u"追加コメント全クリア", u"Comment内の [ ] 部分をすべて削除します（元に戻せません）",
                   self._on_clear_all_brackets)
            add_op(u"採番", u"Comment先頭に通し番号（例: [0001]）を追記します", self._on_number_all)
            add_op(u"解析更新", u"Proxy history 全件を再解析し、集計・一覧を更新します", self._on_refresh_analysis)
            add_op(u"解析結果をCommentへ追記", u"集約判定・ワード照合の結果をCommentへ追記します",
                   self._on_writeback_vuln)
            add_op(u"集約対象に予約色を適用", u"「集約対象」のパケットにのみ予約色を適用します",
                   self._on_apply_agg_color)
            add_op(u"予約色のみクリア", u"現在「予約色」になっているパケットのハイライトだけを解除します",
                   self._on_clear_agg_color)

            ind_box.add(grid, BorderLayout.NORTH)
            outer.add(ind_box)
            outer.add(Box.createVerticalGlue())

            return outer

        def _on_auto_run(self, event):
            do_clear = self.auto_clear_brackets_chk.isSelected()
            do_color = self.auto_apply_color_chk.isSelected()

            # Auto実行はワード照合を含むため、ルール未インポートのまま実行すると
            # Vuln判定が常に空になってしまう。実行前に必ず確認する。
            if self.rules_request or self.rules_response:
                rules_msg = (u"ルール（ワードリスト）は現在 リクエスト用%d件／レスポンス用%d件"
                             u"読み込まれています。" % (len(self.rules_request), len(self.rules_response)))
                rules_type = JOptionPane.QUESTION_MESSAGE
            else:
                rules_msg = (u"ルール（ワードリスト）がまだ読み込まれていません。\n"
                             u"このまま実行すると、ワード照合(Vuln)は常に「該当なし」になります。\n"
                             u"（[ルール]タブで word.csv 等をインポートしてからの実行を推奨します）")
                rules_type = JOptionPane.WARNING_MESSAGE
            ret = JOptionPane.showConfirmDialog(
                self.main_panel,
                rules_msg + u"\n\nこの内容でAuto実行を開始しますか？",
                u"ルールインポートの確認",
                JOptionPane.YES_NO_OPTION,
                rules_type)
            if ret != JOptionPane.YES_OPTION:
                self._log(u"Auto実行をキャンセルしました（ルール未確認）。")
                return

            if do_clear:
                ret = JOptionPane.showConfirmDialog(
                    self.main_panel,
                    u"Auto実行に「追加コメント全クリア」が含まれています。\n"
                    u"HTTP history 全件の Comment から、[ ... ] で囲まれた部分をすべて削除します\n"
                    u"（このツールが書いたマーカーだけでなく、ご自身が手動で書いた [ ] のメモも含みます）。\n\n"
                    u"この操作は元に戻せません。Auto実行を開始しますか？",
                    u"Auto実行の確認",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE)
                if ret != JOptionPane.YES_OPTION:
                    self._log(u"Auto実行をキャンセルしました。")
                    return
            import threading
            t = threading.Thread(target=self._auto_run_worker, args=(do_clear, do_color))
            t.daemon = True
            t.start()

        def _auto_run_worker(self, do_clear, do_color):
            """Auto実行本体。既存の各workerメソッドをそのまま順番に呼び出すだけで、
            ロジックの重複や、個別実行との挙動の食い違いを避ける。
            すべて同一スレッド上で順に呼ぶため、実行順序が保証される
            （解析結果は解析更新直後の状態のまま、色適用・Comment追記に使われる）。"""
            self._log(u"==== Auto実行を開始します ====")
            try:
                if do_clear:
                    self._log(u"[Auto] 追加コメント全クリアを実行します...")
                    self._clear_all_brackets_worker()
                self._log(u"[Auto] 採番を実行します...")
                self._number_all_worker()
                self._log(u"[Auto] 解析更新を実行します...")
                self._refresh_analysis_worker()
                if do_color:
                    self._log(u"[Auto] 集約対象に予約色を適用します...")
                    self._apply_agg_color_worker()
                self._log(u"[Auto] 解析結果をCommentへ追記します...")
                self._writeback_vuln_worker()
                self._log(u"==== Auto実行が完了しました ====")
            except Exception as e:
                self._log(u"Auto実行中にエラーが発生しました: %s" % str(e))

        # --- ルールタブ ---
        # [ルール]タブは上下2段に分かれている（① リクエスト用ルール／② レスポンス用ルール）。
        # 見た目・操作は完全に同一で、対象がリクエストかレスポンスかだけが異なるため、
        # _build_one_rules_subpanel(scope) 以下のハンドラ群はすべて scope("request"/"response")
        # を引数に取り、対応するインスタンス変数（例: self.rules_table_model_request /
        # self.rules_table_model_response）を getattr/setattr 経由で読み書きする。
        def _build_rules_panel(self):
            split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            split.setTopComponent(self._build_one_rules_subpanel("request"))
            split.setBottomComponent(self._build_one_rules_subpanel("response"))
            split.setResizeWeight(0.5)  # リクエスト/レスポンスは対等な関係のため均等割り
            return split

        def _build_one_rules_subpanel(self, scope):
            title = u"① リクエスト用ルール" if scope == "request" else u"② レスポンス用ルール"
            panel = JPanel(BorderLayout())
            title_label = JLabel(title)
            title_label.setFont(title_label.getFont().deriveFont(Font.BOLD))
            panel.add(title_label, BorderLayout.PAGE_START)

            # 「ヒット状況」「ヒット数」列は、[解析]タブで[解析更新]を実行するたびに更新される
            # 目印。解析未実施、またはルール変更後はそれぞれ "-" / 0 のまま。
            table_model = DefaultTableModel(
                [], [u"wordlist1 (/区切りでOR)", u"wordlist2 (/区切りでOR)", u"Vuln-No", u"comment",
                     u"ヒット状況", u"ヒット数"])
            setattr(self, "rules_table_model_" + scope, table_model)
            table = JTable(table_model)
            setattr(self, "rules_table_" + scope, table)

            table_panel = JPanel(BorderLayout())
            table_panel.add(JScrollPane(table), BorderLayout.CENTER)

            top = JPanel(FlowLayout(FlowLayout.LEFT))
            btn_load = JButton(u"CSVロード...", actionPerformed=lambda e, s=scope: self._on_load_csv(e, s))
            btn_add = JButton(u"行追加", actionPerformed=lambda e, s=scope: self._on_add_rule_row(e, s))
            btn_del = JButton(u"選択行削除", actionPerformed=lambda e, s=scope: self._on_del_rule_row(e, s))
            btn_apply = JButton(u"表からルール反映",
                                 actionPerformed=lambda e, s=scope: self._on_apply_rules_from_table(e, s))
            top.add(btn_load)
            top.add(btn_add)
            top.add(btn_del)
            top.add(btn_apply)
            table_panel.add(top, BorderLayout.NORTH)

            bottom = JPanel(FlowLayout(FlowLayout.LEFT))
            bottom.add(JLabel(u"結合条件(wordlist1 と wordlist2):"))
            rb_and = JRadioButton(u"AND", True)
            rb_or = JRadioButton(u"OR", False)
            setattr(self, "rb_and_" + scope, rb_and)
            setattr(self, "rb_or_" + scope, rb_or)
            grp = ButtonGroup()
            grp.add(rb_and)
            grp.add(rb_or)
            rb_and.addActionListener(lambda e, s=scope: self._set_and_or("AND", s))
            rb_or.addActionListener(lambda e, s=scope: self._set_and_or("OR", s))
            bottom.add(rb_and)
            bottom.add(rb_or)
            mapping_label = JLabel(u"")
            setattr(self, "mapping_label_" + scope, mapping_label)
            bottom.add(mapping_label)
            table_panel.add(bottom, BorderLayout.SOUTH)

            panel.add(table_panel, BorderLayout.CENTER)
            return panel

        def _set_and_or(self, mode, scope):
            setattr(self, "and_or_mode_" + scope, mode)
            label = u"リクエスト用" if scope == "request" else u"レスポンス用"
            self._log(u"%sルールの結合条件を %s に変更しました。" % (label, mode))

        def _on_load_csv(self, event, scope):
            label = u"リクエスト用" if scope == "request" else u"レスポンス用"
            chooser = JFileChooser()
            chooser.setDialogTitle(u"%sワードリストCSVを選択（word.csv互換 / list1,list2,VulnNo形式）" % label)
            ret = chooser.showOpenDialog(self.main_panel)
            if ret != JFileChooser.APPROVE_OPTION:
                return
            path = chooser.getSelectedFile().getAbsolutePath()
            try:
                f = open(path, "rb")
                try:
                    raw = f.read()
                finally:
                    f.close()
                # 生バイトのまま csv.reader に渡すと、日本語等の非ASCII文字が
                # 文字化けする（例: UTF-8の各バイトがLatin-1として解釈される）ため、
                # 先にエンコーディングを判定する。
                # ただし Python 2 の csv モジュールは unicode の直接入力を正しく扱えないため
                # （非ASCII文字でエラーになったり読み込めなくなったりする）、csv.reader には
                # 常に UTF-8 の bytes を渡し、分割後の各フィールドを個別に decode する
                # （Python 2 csv モジュールの定石パターン）。
                text, enc_used = decode_csv_bytes(raw)
                utf8_bytes = text.encode("utf-8")
                rows = []
                for r in csv.reader(utf8_bytes.splitlines()):
                    rows.append([cell.decode("utf-8") for cell in r])
                rules, mapping_desc = build_rules_from_rows(rows)
                setattr(self, "rules_" + scope, rules)
                setattr(self, "rules_mapping_desc_" + scope, mapping_desc)
                self._refresh_rules_table(scope)
                getattr(self, "mapping_label_" + scope).setText(mapping_desc)
                self._log(u"%sCSVをロードしました: %s （%d件のルール、文字コード: %s）"
                          % (label, path, len(rules), enc_used))
                self._log(mapping_desc)
            except Exception as e:
                self._log(u"%sCSVロードに失敗しました: %s" % (label, str(e)))
                JOptionPane.showMessageDialog(self.main_panel, str(e), u"CSVロードエラー",
                                               JOptionPane.ERROR_MESSAGE)

        def _refresh_rules_table(self, scope):
            table_model = getattr(self, "rules_table_model_" + scope)
            rules = getattr(self, "rules_" + scope)

            def do_update():
                table_model.setRowCount(0)
                for r in rules:
                    table_model.addRow(
                        ["/".join(r["list1"]), "/".join(r["list2"]), r["vuln_no"], r.get("comment", ""),
                         u"-", 0])
            SwingUtilities.invokeLater(do_update)
            # ルールが入れ替わったため、直近の解析結果に基づく目印もリセットする
            # （古いルール構成に対するヒット状況を新しい表に誤って表示しないように）。
            # 削除は該当スコープのみに限定する（片方の再読込がもう片方の、まだ有効な
            # ヒット状況表示を巻き込んで消してしまわないように）。
            matched_attr = "_matched_vuln_nos_" + scope
            counts_attr = "_vuln_hit_counts_" + scope
            if hasattr(self, matched_attr):
                delattr(self, matched_attr)
            if hasattr(self, counts_attr):
                delattr(self, counts_attr)

        def _on_add_rule_row(self, event, scope):
            getattr(self, "rules_table_model_" + scope).addRow(["", "", "", "", u"-", 0])

        def _on_del_rule_row(self, event, scope):
            table = getattr(self, "rules_table_" + scope)
            table_model = getattr(self, "rules_table_model_" + scope)
            rows = table.getSelectedRows()
            for i in sorted(rows, reverse=True):
                table_model.removeRow(i)

        def _on_apply_rules_from_table(self, event, scope):
            """テーブルの内容（ユーザーが手で編集した分も含む）を rules_<scope> に反映する。"""
            label = u"リクエスト用" if scope == "request" else u"レスポンス用"
            try:
                table = getattr(self, "rules_table_" + scope)
                table_model = getattr(self, "rules_table_model_" + scope)
                # Swingの既知の挙動として、セルを編集中（Tab/Enter等で確定する前）に
                # ボタンをクリックしても、直前に入力した内容は自動ではテーブルモデルに
                # 反映されない。[行追加]で新規行を作り、セルに入力した直後にこのボタンを
                # 押すと最後の1セルの入力が抜け落ちる、という形で顕在化するため、
                # 読み取り前に明示的に編集を確定させる。
                editor = table.getCellEditor()
                if editor is not None:
                    editor.stopCellEditing()

                n = table_model.getRowCount()
                rules = []
                for i in range(n):
                    l1raw = table_model.getValueAt(i, 0)
                    l2raw = table_model.getValueAt(i, 1)
                    vuln_raw = table_model.getValueAt(i, 2)
                    comment_raw = table_model.getValueAt(i, 3)
                    l1 = [w.strip() for w in safe_text(l1raw).split(u"/") if w.strip()]
                    l2 = [w.strip() for w in safe_text(l2raw).split(u"/") if w.strip()]
                    vuln = safe_text(vuln_raw).strip()
                    comment = safe_text(comment_raw).strip()
                    if not vuln or (not l1 and not l2):
                        continue
                    rules.append({"vuln_no": vuln, "list1": l1, "list2": l2, "comment": comment})
                setattr(self, "rules_" + scope, rules)
                self._log(u"%s表の内容を反映しました（%d件のルール）。" % (label, len(rules)))
            except Exception as e:
                self._log(u"%s表からルール反映でエラーが発生しました: %s" % (label, safe_text(e)))

        def _refresh_rules_hit_status_for(self, table_model, matched_set, hit_counts):
            """[解析]タブでの解析結果（matched_set/hit_counts）をもとに、ルールタブの表に
            「ヒットあり」／「★ 未ヒット」の目印とヒット数を付ける。リクエスト用・レスポンス用
            それぞれのテーブルに対して個別に呼び出す（_refresh_analysis_worker参照）。
            ヒット数は「そのVuln-Noがヒットしたパケットの件数」（1パケット内で複数箇所
            ヒットしても1件と数える。集約対象の重複パケットも特別扱いせずそのまま数える）。"""
            def do_update():
                n = table_model.getRowCount()
                for i in range(n):
                    vn = table_model.getValueAt(i, 2)
                    vn = safe_text(vn).strip()
                    if not vn:
                        continue
                    status = u"ヒットあり" if vn in matched_set else u"★ 未ヒット"
                    table_model.setValueAt(status, i, 4)
                    table_model.setValueAt(hit_counts.get(vn, 0), i, 5)
            SwingUtilities.invokeLater(do_update)

        # --- 解析タブ ---
        def _build_analysis_panel(self):
            panel = JPanel(BorderLayout())
            top_box = JPanel()
            top_box.setLayout(BoxLayout(top_box, BoxLayout.Y_AXIS))

            top = JPanel(FlowLayout(FlowLayout.LEFT))
            btn = JButton(u"解析更新（HTTP history全件を再解析）", actionPerformed=self._on_refresh_analysis)
            top.add(btn)
            btn_writeback = JButton(u"解析結果をCommentへ追記（集約判定＋ワード照合）", actionPerformed=self._on_writeback_vuln)
            top.add(btn_writeback)
            self.analysis_status = JLabel(u"未解析")
            top.add(self.analysis_status)
            top.setAlignmentX(0.0)
            top_box.add(top)

            scope_row = JPanel(FlowLayout(FlowLayout.LEFT))
            # 既定でON。Burp の Target Scope 設定（Target タブ → Scope）で対象を絞り込む。
            # Scopeを何も設定していない状態でこのままにすると、解析結果が0件になり得るため
            # （_refresh_analysis_worker側でその場合はログにヒントを出す）、Scope未設定の場合は
            # 先にBurpでScopeを設定するか、このチェックを外してください。
            self.scope_only_chk = JCheckBox(u"Burp Target Scope 内のみを解析対象にする", True)
            scope_row.add(self.scope_only_chk)
            scope_row.add(JLabel(u"（Target タブの Scope 設定を使用。次回の[解析更新]から反映。既定でON）"))
            scope_row.setAlignmentX(0.0)
            top_box.add(scope_row)

            panel.add(top_box, BorderLayout.NORTH)

            split = JSplitPane(JSplitPane.VERTICAL_SPLIT)

            # 種別ごとの集計（分類=画面／画面更新(SPA)／API／静的 の件数）。
            # 表示対象は、採番済みの番号（Comment先頭の[NNNN]）で範囲を絞り込める
            # （空欄なら全件が対象）。この範囲は、下のワード照合一覧にも同じ範囲で適用される。
            summary_panel = JPanel(BorderLayout())
            summary_filter_row = JPanel(FlowLayout(FlowLayout.LEFT))
            summary_filter_row.add(JLabel(u"表示対象の採番範囲（空欄で全件。下のワード照合一覧にも適用）:"))
            self.summary_from_field = JTextField("", 6)
            summary_filter_row.add(self.summary_from_field)
            summary_filter_row.add(JLabel(u"〜"))
            self.summary_to_field = JTextField("", 6)
            summary_filter_row.add(self.summary_to_field)
            summary_filter_row.add(JButton(u"表示を更新", actionPerformed=self._on_refresh_summary))
            summary_panel.add(summary_filter_row, BorderLayout.NORTH)

            # 件数(集約対象を含む)=履歴上のパケット単純カウント（集約対象の重複も1件ずつ数える）。
            # 件数(集約対象を除く)=集約対象を除いた件数（＝代表+単独のみ。同一操作の繰り返しは
            # 1グループ=1件として数えるため、実質的な「操作の種類の数」に近くなる）。
            # 画面/API/静的は集約判定の対象外のため、この2列は常に同じ値になる
            # （集約対象になり得るのは画面更新(SPA)のみ）。
            self.summary_table_model = DefaultTableModel(
                [], [u"分類", u"件数(集約対象を含む)", u"件数(集約対象を除く)"])
            self.summary_table = JTable(self.summary_table_model)
            summary_inner = JPanel(BorderLayout())
            summary_inner.add(JLabel(u"種別ごとの集計"), BorderLayout.NORTH)
            summary_inner.add(JScrollPane(self.summary_table), BorderLayout.CENTER)
            summary_panel.add(summary_inner, BorderLayout.CENTER)
            self.summary_status = JLabel(u"未集計")
            summary_panel.add(self.summary_status, BorderLayout.SOUTH)
            split.setTopComponent(summary_panel)

            # 表の1列目は Comment（HTTP history の Comments 列と見比べて紐づけるため。
            # 解析時点の内部通し番号Noは history 上の表示と対応しないため列に出さない）
            # AggRole列は、そのパケットが集約対象か否かを一覧上で判別できるよう、
            # Comment列のすぐ次に配置している。続けて Method/URL でどの通信かを
            # 一覧上で確認できるようにし、その後ろに分類・Vuln-No等の解析結果を並べる。
            # ルールComment列は word.csv の comment 列（あれば）の内容をそのまま表示する。
            # 「ヒット元」列は、そのVuln-Noが①リクエスト用ルール／②レスポンス用ルールの
            # どちらでヒットしたか（両方の表に同じVuln-Noがあり両方でヒットした場合は
            # 「リクエスト+レスポンス」）を示す。Vuln-No列のすぐ次に配置している。
            # 「ヒットしたワードとロケーション」「ルールComment」は長文になり得るため、列幅内で
            # 見切れる問題を避けるべく、表の下に選択行の内容を表示する専用欄を別途設ける
            # （列自体は一覧性のために残す）。
            self._vuln_col_rule_comment = 8
            self.vuln_table_model = DefaultTableModel(
                [], ["Comment", u"AggRole", u"Method", u"URL", u"分類", "Vuln-No", u"ヒット元",
                     u"ヒットしたワードとロケーション", u"ルールComment"])
            self.vuln_table = JTable(self.vuln_table_model)
            self.vuln_table.setAutoCreateRowSorter(True)
            # Vuln-No列は既定だと文字列としての辞書順ソート（1,10,3のように並ぶ）になって
            # しまうため、数値として直感通りに並ぶ自然順コンパレータを設定する。
            self.vuln_table.getRowSorter().setComparator(5, _NaturalOrderComparator())
            self.vuln_table.getSelectionModel().addListSelectionListener(self._on_vuln_row_selected)
            vuln_panel = JPanel(BorderLayout())
            vuln_header = JPanel(FlowLayout(FlowLayout.LEFT))
            vuln_header.add(JLabel(u"ワード照合 一覧（列見出しクリックでソート可）"))
            # 集約対象（同一操作の繰り返し）は代表と同じヒット内容が並ぶだけのことが多く、
            # 一覧が同じ内容の繰り返しで埋まりがちなため、表示から省けるようにする。
            # チェックを変更した時点で（解析済みなら）即座に再描画する。既定でON
            # （まず代表・単独だけの実質的な一覧を見せ、必要な時だけ集約対象も含めて確認する運用）。
            self.vuln_hide_agg_chk = JCheckBox(u"集約対象を除いて表示", True)
            self.vuln_hide_agg_chk.addActionListener(self._on_vuln_filter_changed)
            vuln_header.add(self.vuln_hide_agg_chk)
            btn_export_vuln_csv = JButton(u"この一覧をCSV出力...", actionPerformed=self._on_export_vuln_csv)
            vuln_header.add(btn_export_vuln_csv)
            vuln_panel.add(vuln_header, BorderLayout.NORTH)

            vuln_split = JSplitPane(JSplitPane.VERTICAL_SPLIT)
            vuln_split.setTopComponent(JScrollPane(self.vuln_table))

            # 「ヒットしたワードとロケーション」は、ロケーション/ワードを列として持つ小さな表で
            # 1ヒット=1行ずつ表示する（列の並びはロケーション→ヒットしたワードの順）。
            words_box = JPanel(BorderLayout())
            words_box.add(JLabel(u"選択行: ヒットしたワードとロケーション"), BorderLayout.NORTH)
            self.vuln_detail_words_model = DefaultTableModel([], [u"ロケーション", u"ヒットしたワード"])
            self.vuln_detail_words_table = JTable(self.vuln_detail_words_model)
            words_box.add(JScrollPane(self.vuln_detail_words_table), BorderLayout.CENTER)

            comment_box = JPanel(BorderLayout())
            comment_box.add(JLabel(u"選択行: ルールComment"), BorderLayout.NORTH)
            self.vuln_detail_comment = JTextArea()
            self.vuln_detail_comment.setEditable(False)
            self.vuln_detail_comment.setLineWrap(True)
            self.vuln_detail_comment.setWrapStyleWord(True)
            self.vuln_detail_comment.setFont(Font("Monospaced", Font.PLAIN, 12))
            comment_box.add(JScrollPane(self.vuln_detail_comment), BorderLayout.CENTER)

            detail_panel = JPanel(GridLayout(1, 2, 8, 0))
            detail_panel.add(words_box)
            detail_panel.add(comment_box)
            vuln_split.setBottomComponent(detail_panel)
            vuln_split.setResizeWeight(0.65)

            vuln_panel.add(vuln_split, BorderLayout.CENTER)
            self.vuln_status = JLabel(u"未表示")
            vuln_panel.add(self.vuln_status, BorderLayout.SOUTH)
            split.setBottomComponent(vuln_panel)
            split.setResizeWeight(0.3)

            panel.add(split, BorderLayout.CENTER)
            return panel

        def _on_vuln_row_selected(self, event):
            if event.getValueIsAdjusting():
                return
            view_row = self.vuln_table.getSelectedRow()
            self.vuln_detail_words_model.setRowCount(0)
            if view_row < 0:
                self.vuln_detail_comment.setText(u"")
                return
            # ソート後は表示上の行順とテーブルモデルの行順がずれるため、
            # 必ずconvertRowIndexToModelを経由してからモデル側のインデックスとして使う。
            row = self.vuln_table.convertRowIndexToModel(view_row)
            wl_list = []
            if hasattr(self, "_vuln_row_wl") and 0 <= row < len(self._vuln_row_wl):
                wl_list = self._vuln_row_wl[row]
            for wl in wl_list:
                # format_word_loc_pairs() が作る "word@location" 形式を分解する。
                # ロケーションは常に固定の識別子（path/query/reqHeaders/reqBody）で "@" を
                # 含まないため、末尾側の "@" で区切ればワード側に "@" が含まれていても安全。
                word, sep, loc = wl.rpartition(u"@")
                if not sep:
                    word, loc = wl, u""
                self.vuln_detail_words_model.addRow([loc, word])

            comment = self.vuln_table_model.getValueAt(row, self._vuln_col_rule_comment) or u""
            self.vuln_detail_comment.setText(comment)
            self.vuln_detail_comment.setCaretPosition(0)

            # 選択行のComment先頭にある採番トークン（例 "[0005]"）をクリップボードにコピーする。
            # BurpのHistory検索窓に直接値をセットする公式APIは無いため、コピー＆手動貼り付けで
            # 該当パケットをすぐに絞り込めるようにする代替手段。
            row_comment = self.vuln_table_model.getValueAt(row, 0) or u""
            m = LEADING_NUMBER_RE.match(safe_text(row_comment))
            if m:
                token = m.group(0)
                if self._copy_to_clipboard(token):
                    self._log(u"採番番号 %s をクリップボードにコピーしました"
                              u"（BurpのHistory検索窓に貼り付けると該当パケットを絞り込めます）。" % token)

        def _copy_to_clipboard(self, text):
            try:
                clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                clipboard.setContents(StringSelection(text), None)
                return True
            except Exception as e:
                self._log(u"クリップボードへのコピーに失敗しました: %s" % safe_text(e))
                return False

        def _on_refresh_analysis(self, event):
            import threading
            t = threading.Thread(target=self._refresh_analysis_worker)
            t.daemon = True
            t.start()

        def _refresh_analysis_worker(self):
            try:
                self._log(u"解析を開始します...")
                # 「Burp Target Scope 内のみを解析対象にする」がチェックされている場合、
                # Burp の Target > Scope 設定（callbacks.isInScope）を使って絞り込む。
                # 既定は無効（従来通りhistory全件）。スコープ未設定のユーザーが突然
                # 解析結果0件に見える事故を避けるため、明示的にチェックした場合のみ有効になる。
                # URL取得やスコープ判定自体に失敗した場合は、安全側に倒して除外しない。
                scope_only = self.scope_only_chk.isSelected()
                history = self._callbacks.getProxyHistory()
                packets = []
                no = 0
                skipped_out_of_scope = 0
                for raw_index, item in enumerate(history):
                    try:
                        if scope_only:
                            in_scope = True
                            try:
                                url = self._helpers.analyzeRequest(item).getUrl()
                                in_scope = self._callbacks.isInScope(url)
                            except Exception:
                                in_scope = True
                            if not in_scope:
                                skipped_out_of_scope += 1
                                continue
                        no += 1
                        req = item.getRequest()
                        resp = item.getResponse()
                        svc = item.getHttpService()
                        comment = item.getComment() or ""
                        pkt = analyze_http_item(self._helpers, svc, req, resp, comment)
                        pkt.no = no
                        pkt.vuln_hits_request = match_rules(
                            self.rules_request, pkt.corpus, self.and_or_mode_request)
                        pkt.vuln_hits_response = match_rules(
                            self.rules_response, pkt.resp_corpus, self.and_or_mode_response,
                            location_order=RESPONSE_LOCATION_ORDER)
                        pkt.vuln_hits = merge_vuln_hits(pkt.vuln_hits_request, pkt.vuln_hits_response)
                        packets.append(pkt)
                    except Exception as e:
                        self._log(u"history内 index=%d の解析エラー: %s" % (raw_index + 1, str(e)))

                # 集約対象になり得るのは Aura の SPA通信（cls_code==CLS_SPA）だけに限定する。
                # 画面/API/静的通信は method+pathだけの粗いキーになり得るため（クエリのトークン値等を
                # 見ない）、無関係な別リクエスト（例: /cst/s/otc の異なるワンタイムトークン）が
                # 誤って同一グループに丸められてしまう。それ以外は PacketInfo の初期値のまま
                # （agg_role=単独, agg_group_size=1）とする。
                # SPAのうち descriptor を持たない通信（例: auraCmpDef/auraResources等の
                # コンポーネント定義取得）も対象に含めるが、この場合の agg_key はパラメータの値まで
                # 含めて識別する（compute_agg_key 参照）ため、実際に内容が同じ通信だけが集約される。
                #
                # さらに、同一AggKeyであっても履歴上「連続している（間に他のAggKeyのAura SPA通信を
                # 挟まない）」範囲だけを1グループとみなす（隣接性の条件）。これにより、同じテスト
                # 手続きを時間を空けて何度も繰り返した場合に、離れた場所の実行同士が誤って同一の
                # 集約グループに丸められてしまうことを防ぐ（例: フォーム入力テストを1回目に実施し、
                # 別の操作を挟んでから2回目を実施した場合、1回目と2回目は別グループとして扱う）。
                eligible = sorted(
                    [p for p in packets if p.cls_code == CLS_SPA],
                    key=lambda p: p.no)
                runs = []
                cur_run = []
                cur_key = None
                for pkt in eligible:
                    if cur_run and pkt.agg_key == cur_key:
                        cur_run.append(pkt)
                    else:
                        if cur_run:
                            runs.append(cur_run)
                        cur_run = [pkt]
                        cur_key = pkt.agg_key
                if cur_run:
                    runs.append(cur_run)

                groups = {}
                for run in runs:
                    rep_pkt = run[0]
                    size = len(run)
                    for pkt in run:
                        pkt.agg_group_size = size
                        pkt.agg_rep_no = rep_pkt.no
                        pkt.agg_rep_pkt = rep_pkt
                        if size <= 1:
                            pkt.agg_role = u"単独"
                        elif pkt is rep_pkt:
                            pkt.agg_role = u"代表"
                        else:
                            pkt.agg_role = u"集約対象"
                    # 表示/互換用: 同一AggKeyの複数run（＝離れた場所での繰り返し）はキーごとに
                    # まとめて保持するが、代表/集約対象の判定自体は各runごとに独立して行っている。
                    groups.setdefault(rep_pkt.agg_key, []).extend(run)

                index_by_identity = {}
                for pkt in packets:
                    index_by_identity[pkt.identity] = pkt

                self.index_by_identity = index_by_identity
                self.agg_groups = groups
                self._packets_cache = packets

                # 解析済みパケットのどれかにヒットしたVuln-Noの集合とヒット数（パケット単位）。
                # [ルール]タブの表の「ヒット状況」「ヒット数」列の判定に使う
                # （_refresh_rules_hit_status_for）。マージ後のpkt.vuln_hitsではなく、
                # マージ前のリクエスト側/レスポンス側それぞれのヒットを個別に集計する
                # （match_rulesの再実行はしない）。
                matched_vuln_nos_request = set()
                vuln_hit_counts_request = {}
                matched_vuln_nos_response = set()
                vuln_hit_counts_response = {}
                for pkt in packets:
                    seen_req = set(vuln_no for vuln_no, hits in pkt.vuln_hits_request)
                    for vuln_no in seen_req:
                        matched_vuln_nos_request.add(vuln_no)
                        vuln_hit_counts_request[vuln_no] = vuln_hit_counts_request.get(vuln_no, 0) + 1
                    seen_resp = set(vuln_no for vuln_no, hits in pkt.vuln_hits_response)
                    for vuln_no in seen_resp:
                        matched_vuln_nos_response.add(vuln_no)
                        vuln_hit_counts_response[vuln_no] = vuln_hit_counts_response.get(vuln_no, 0) + 1
                self._matched_vuln_nos_request = matched_vuln_nos_request
                self._vuln_hit_counts_request = vuln_hit_counts_request
                self._matched_vuln_nos_response = matched_vuln_nos_response
                self._vuln_hit_counts_response = vuln_hit_counts_response
                self._refresh_rules_hit_status_for(
                    self.rules_table_model_request, matched_vuln_nos_request, vuln_hit_counts_request)
                self._refresh_rules_hit_status_for(
                    self.rules_table_model_response, matched_vuln_nos_response, vuln_hit_counts_response)

                agg_run_count = sum(1 for run in runs if len(run) > 1)
                self._populate_analysis_tables(packets)
                if scope_only:
                    self._log(u"解析完了: %d パケット（Scope外 %d 件を除外）/ 集約グループ(隣接run) %d 件"
                              % (len(packets), skipped_out_of_scope, agg_run_count))
                    if len(packets) == 0 and skipped_out_of_scope > 0:
                        self._log(u"※ 全件がScope外と判定されました。Burpの Target タブで "
                                  u"Scope（Include in scope）が設定されているか確認するか、"
                                  u"[解析]タブの「Burp Target Scope 内のみを解析対象にする」の"
                                  u"チェックを外して再度[解析更新]してください。")
                else:
                    self._log(u"解析完了: %d パケット / 集約グループ(隣接run) %d 件" % (len(packets), agg_run_count))

                def upd_status():
                    self.analysis_status.setText(u"解析済み: %d パケット" % len(packets))
                SwingUtilities.invokeLater(upd_status)
            except Exception as e:
                self._log(u"解析中にエラーが発生しました: %s" % str(e))

        def _populate_analysis_tables(self, packets):
            self._apply_range_and_populate(packets)

        def _leading_number_int(self, comment):
            """Comment先頭の採番トークン（[0005]等）から数値部分だけを取り出す。
            接頭辞つき（例: [REQ0005]）でも末尾の数字列を拾う。無ければ None。"""
            s = extract_leading_number(comment)
            if not s:
                return None
            m = re.search(r'(\d+)$', s)
            if not m:
                return None
            try:
                return int(m.group(1))
            except Exception:
                return None

        def _get_summary_range(self):
            def parse_int(field):
                s = (field.getText() or "").strip()
                if not s:
                    return None
                try:
                    return int(s)
                except Exception:
                    return None
            return parse_int(self.summary_from_field), parse_int(self.summary_to_field)

        def _filter_packets_by_range(self, packets):
            """採番範囲（[解析]タブの入力欄）でパケットを絞り込む。
            範囲が未指定（両欄空欄）なら全件を返す。範囲指定時、未採番のパケットは対象外。
            戻り値: (filtered_packets, range_active)"""
            lo, hi = self._get_summary_range()
            range_active = (lo is not None) or (hi is not None)
            if not range_active:
                return list(packets), False
            filtered = []
            for pkt in packets:
                n = self._leading_number_int(pkt.comment)
                if n is None:
                    continue
                if lo is not None and n < lo:
                    continue
                if hi is not None and n > hi:
                    continue
                filtered.append(pkt)
            return filtered, True

        def _on_refresh_summary(self, event):
            if not self._packets_cache_exists():
                self._log(u"先に [解析更新] を実行してください。")
                return
            self._apply_range_and_populate(self._packets_cache)

        def _apply_range_and_populate(self, packets):
            """採番範囲での絞り込みを、種別ごとの集計とワード照合一覧の**両方**に
            同じ範囲で適用する（片方だけ範囲外のデータが残って表示がずれることのないように、
            必ずこの1箇所を経由して両テーブルを更新する）。"""
            filtered, range_active = self._filter_packets_by_range(packets)

            # 件数(含む): 履歴上のパケットをそのまま数える（集約対象の重複も1件ずつ）。
            # 件数(除く): 集約対象（agg_role=="集約対象"）を除いて数える。同一操作の繰り返しは
            # 代表1件だけがカウントされるため、実質的な「操作の種類の数」に近づく。
            counts_incl = {}
            counts_excl = {}
            for pkt in filtered:
                label = CLS_LABELS.get(pkt.cls_code, pkt.cls_code)
                counts_incl[label] = counts_incl.get(label, 0) + 1
                if pkt.agg_role != u"集約対象":
                    counts_excl[label] = counts_excl.get(label, 0) + 1
            excl_total = sum(1 for p in filtered if p.agg_role != u"集約対象")
            comment_by_vuln = self._build_comment_by_vuln()

            def do_update():
                # ワード照合一覧の「集約対象を除いて表示」チェックを、この集計欄のステータス行にも
                # 反映する（テーブル自体は常に「含む/除く」の両方の列を出すが、ステータス行は
                # 実際に下のワード照合一覧が対象にしているパケット数と一致させ、チェックを
                # 切り替えた瞬間に数字が連動するようにする）。
                hide_agg = self.vuln_hide_agg_chk.isSelected()
                display_count = excl_total if hide_agg else len(filtered)
                mode_label = u"集約対象を除く" if hide_agg else u"集約対象を含む"

                self.summary_table_model.setRowCount(0)
                for code in (CLS_SCREEN, CLS_SPA, CLS_API, CLS_STATIC):
                    label = CLS_LABELS[code]
                    self.summary_table_model.addRow(
                        [label, counts_incl.get(label, 0), counts_excl.get(label, 0)])
                self.summary_table_model.addRow([u"合計", len(filtered), excl_total])
                if range_active:
                    self.summary_status.setText(
                        u"表示対象: %d / %d パケット（%s。採番範囲で絞り込み中。未採番は対象外。"
                        u"下のワード照合一覧も同じ範囲・同じ集約対象フィルタです）"
                        % (display_count, len(packets), mode_label))
                else:
                    self.summary_status.setText(
                        u"表示対象: %d パケット（%s・全件）" % (display_count, mode_label))

                self.vuln_table_model.setRowCount(0)
                # 選択行の「ヒットしたワードとロケーション」詳細表（ロケーション/ワードの
                # 構造化データ）を、表の行と同じ順序で別途保持しておく（テーブル上は
                # 表示用に結合した文字列を1セルに入れているため、選択時に元データへ
                # 戻すためのもの）。
                self._vuln_row_wl = []
                shown = 0
                hidden = 0
                for pkt in filtered:
                    if hide_agg and pkt.agg_role == u"集約対象":
                        hidden += len(pkt.vuln_hits)
                        continue
                    cls_label = CLS_LABELS.get(pkt.cls_code, pkt.cls_code)
                    req_vuln_nos = set(vn for vn, _ in pkt.vuln_hits_request)
                    resp_vuln_nos = set(vn for vn, _ in pkt.vuln_hits_response)
                    for vuln_no, hits in pkt.vuln_hits:
                        wl_list = format_word_loc_pairs(hits)
                        scope_label = hit_scope_label(vuln_no, req_vuln_nos, resp_vuln_nos)
                        self.vuln_table_model.addRow([
                            pkt.comment, pkt.agg_role, pkt.method, pkt.url,
                            cls_label, vuln_no, scope_label, ", ".join(wl_list),
                            comment_by_vuln.get(vuln_no, ""),
                        ])
                        self._vuln_row_wl.append(wl_list)
                        shown += 1
                if hide_agg and hidden:
                    self.vuln_status.setText(u"ワード照合一覧: %d 件表示（集約対象の %d 件を非表示中）"
                                              % (shown, hidden))
                else:
                    self.vuln_status.setText(u"ワード照合一覧: %d 件表示" % shown)
            SwingUtilities.invokeLater(do_update)

        def _on_vuln_filter_changed(self, event):
            """「集約対象を除いて表示」チェックの変更を、解析済みなら即座に反映する。"""
            if self._packets_cache_exists():
                self._apply_range_and_populate(self._packets_cache)

        def _on_export_vuln_csv(self, event):
            if not self._packets_cache_exists():
                self._log(u"先に [解析更新] を実行してください。")
                return
            chooser = JFileChooser()
            chooser.setDialogTitle(u"ワード照合一覧CSVの保存先を選択")
            chooser.setSelectedFile(File("sf_helper_vuln_export.csv"))
            ret = chooser.showSaveDialog(self.main_panel)
            if ret != JFileChooser.APPROVE_OPTION:
                return
            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.lower().endswith(".csv"):
                path += ".csv"
            import threading
            t = threading.Thread(target=self._export_vuln_csv_worker, args=(path,))
            t.daemon = True
            t.start()

        def _export_vuln_csv_worker(self, path):
            """ワード照合一覧（現在の表示条件＝採番範囲・「集約対象を除いて表示」）と
            同じ行セットをCSV出力する。各行に該当パケットのrequest/responseを追加する
            （liveのProxy historyからidentityで引き当てる。①採番/③照合と同じ突合方法）。
            Excel表示を想定し、request/responseは改行をスペースに置換のうえ
            flatten_for_csv() で長さを制限し、省略時は "<---snip--->" を付ける。
            Comment列は、本ツールが末尾に追記する解析マーカー（[SF ...]。SF_MARKER_RE）を
            除いた部分（＝採番トークンとユーザーが記載したコメントまで）のみを出力する。"""
            if not self._packets_cache_exists():
                self._log(u"先に [解析更新] を実行してください。")
                return
            filtered, range_active = self._filter_packets_by_range(self._packets_cache)
            hide_agg = self.vuln_hide_agg_chk.isSelected()
            comment_by_vuln = self._build_comment_by_vuln()
            history = self._callbacks.getProxyHistory()

            def _identity_of(item):
                req = item.getRequest()
                svc = item.getHttpService()
                req_str = self._helpers.bytesToString(req) if req is not None else ""
                host = svc.getHost() if svc else ""
                port = svc.getPort() if svc else 0
                proto = svc.getProtocol() if svc else ""
                return (host, port, proto, req_str)

            item_by_identity = {}
            for item in history:
                try:
                    item_by_identity[_identity_of(item)] = item
                except Exception:
                    continue

            header = [u"Comment", u"AggRole", u"Method", u"URL", u"分類", u"Vuln-No", u"ヒット元",
                      u"ヒットしたワード@ロケーション", u"ルールComment",
                      u"Request", u"Response"]
            rows = []
            for pkt in filtered:
                if hide_agg and pkt.agg_role == u"集約対象":
                    continue
                if not pkt.vuln_hits:
                    continue
                cls_label = CLS_LABELS.get(pkt.cls_code, pkt.cls_code)
                comment_display = SF_MARKER_RE.sub(u"", pkt.comment or u"")
                item = item_by_identity.get(pkt.identity)
                req_text = u""
                resp_text = u""
                if item is not None:
                    try:
                        req_bytes = item.getRequest()
                        if req_bytes is not None:
                            req_text = safe_text(self._helpers.bytesToString(req_bytes))
                    except Exception:
                        req_text = u""
                    try:
                        resp_bytes = item.getResponse()
                        if resp_bytes is not None:
                            resp_text = safe_text(self._helpers.bytesToString(resp_bytes))
                    except Exception:
                        resp_text = u""
                req_vuln_nos = set(vn for vn, _ in pkt.vuln_hits_request)
                resp_vuln_nos = set(vn for vn, _ in pkt.vuln_hits_response)
                for vuln_no, hits in pkt.vuln_hits:
                    wl_list = format_word_loc_pairs(hits)
                    scope_label = hit_scope_label(vuln_no, req_vuln_nos, resp_vuln_nos)
                    rows.append([
                        comment_display, pkt.agg_role, pkt.method, pkt.url, cls_label, vuln_no,
                        scope_label, u", ".join(wl_list), comment_by_vuln.get(vuln_no, u""),
                        flatten_for_csv(req_text), flatten_for_csv(resp_text),
                    ])

            try:
                f = open(path, "wb")
                try:
                    f.write(u"\ufeff".encode("utf-8"))
                    writer = csv.writer(f)
                    writer.writerow([safe_text(c).encode("utf-8") for c in header])
                    for row in rows:
                        writer.writerow([safe_text(c).encode("utf-8") for c in row])
                finally:
                    f.close()
                self._log(u"ワード照合一覧をCSV出力しました: %s (%d 行)" % (safe_text(path), len(rows)))
            except Exception as e:
                self._log(u"CSV出力エラー: %s" % safe_text(e))

        def _on_writeback_vuln(self, event):
            import threading
            t = threading.Thread(target=self._writeback_vuln_worker)
            t.daemon = True
            t.start()

        def _writeback_vuln_worker(self):
            """解析済みの全パケットのCommentへ、集約判定（代表/集約対象/単独）と
            ワード照合ヒット（あれば）を [SF Agg=... Vuln=...] の形式で追記する。
            「集約対象か否か」は必ず書き込まれる（Vuln有無に関わらず）。
            「集約対象」の場合は、代表パケットの"現在の"Commentから①採番の番号
            （例 [0005]）を読み取り、"→代表[0005]" として、どの代表に集約されたかを
            番号で参照できるようにする（先に①採番タブで採番しておくことを推奨）。
            既存メモは保持し、末尾に追記する（採番①はComment先頭を使うため衝突しない）。
            以前このツールが書いた同種マーカー（旧版の [Vuln: ...] 形式含む）があれば
            置き換える（何度実行しても重複しない）。"""
            if not self._packets_cache_exists():
                self._log(u"先に [解析] タブで [解析更新] を実行してください。")
                return
            history = self._callbacks.getProxyHistory()
            comment_by_vuln = self._build_comment_by_vuln()

            def _identity_of(item):
                req = item.getRequest()
                svc = item.getHttpService()
                req_str = self._helpers.bytesToString(req) if req is not None else ""
                host = svc.getHost() if svc else ""
                port = svc.getPort() if svc else 0
                proto = svc.getProtocol() if svc else ""
                return (host, port, proto, req_str)

            # 代表パケットの"現在の"Comment（①採番の結果を含む）を参照するため、
            # identity -> 実際のitem のマップを先に作っておく。
            item_by_identity = {}
            for item in history:
                try:
                    item_by_identity[_identity_of(item)] = item
                except Exception:
                    continue

            count = 0
            for item in history:
                try:
                    key = _identity_of(item)
                    pkt = self.index_by_identity.get(key)
                    if pkt is None:
                        continue

                    rep_comment = None
                    if pkt.agg_role == u"集約対象" and pkt.agg_rep_pkt is not None:
                        rep_item = item_by_identity.get(pkt.agg_rep_pkt.identity)
                        if rep_item is not None:
                            rep_comment = rep_item.getComment() or ""

                    marker = format_sf_marker(pkt.agg_role, pkt.agg_group_size, pkt.vuln_hits, rep_comment,
                                               pkt.cls_code, comment_by_vuln)
                    old = item.getComment() or ""
                    base = SF_MARKER_RE.sub("", old)
                    new_comment = (base + " " + marker) if base else marker
                    item.setComment(new_comment)
                    count += 1
                except Exception as e:
                    self._log(u"Comment追記エラー: %s" % str(e))
            self._log(u"解析結果（集約判定＋ワード照合）をCommentへ追記しました: %d 件" % count)

        # --- 採番タブ ---
        def _build_numbering_panel(self):
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

            row1 = JPanel(FlowLayout(FlowLayout.LEFT))
            row1.add(JLabel(u"接頭辞:"))
            self.num_prefix_field = JTextField(NUMBER_PREFIX_DEFAULT, 8)
            row1.add(self.num_prefix_field)
            row1.add(JLabel(u"桁数:"))
            self.num_digits_field = JTextField(str(NUMBER_DIGITS_DEFAULT), 3)
            row1.add(self.num_digits_field)
            row1.add(JLabel(u"開始番号:"))
            self.num_start_field = JTextField("1", 5)
            row1.add(self.num_start_field)
            panel.add(row1)

            row2 = JPanel(FlowLayout(FlowLayout.LEFT))
            btn_all = JButton(u"全history採番", actionPerformed=self._on_number_all)
            btn_clear = JButton(u"採番解除（全history）", actionPerformed=self._on_number_clear_all)
            row2.add(btn_all)
            row2.add(btn_clear)
            panel.add(row2)

            row3 = JPanel(FlowLayout(FlowLayout.LEFT))
            btn_clear_brackets = JButton(u"追加コメント全クリア（[ ]を全削除）",
                                          actionPerformed=self._on_clear_all_brackets)
            row3.add(btn_clear_brackets)
            panel.add(row3)

            note = JTextArea(
                u"注記:\n"
                u"・番号は Comment 欄の先頭に「[番号] 」の形で追加されます（既存メモは保持）。\n"
                u"・番号は実行時点の HTTP history の並び順（1始まり）で採番されます。\n"
                u"・トラフィック取得が完了してから、Save items でXML出力する直前に実行することを推奨します。\n"
                u"・右クリックメニューからも選択したパケットのみ採番できます。\n"
                u"・[採番解除]は、Comment先頭の採番トークンだけを取り除きます（安全・狭い範囲）。\n"
                u"・[追加コメント全クリア]は、このツールが書いた採番/解析マーカーに限らず、\n"
                u"　Comment内にある [ ... ] 形式の部分を**すべて**（先頭・末尾・入れ子問わず）\n"
                u"　削除します。手動で [ ] を使ったメモも一緒に消えるため注意してください（実行前に確認あり）。")
            note.setEditable(False)
            note.setOpaque(False)
            panel.add(note)
            return panel

        def _get_numbering_params(self):
            prefix = self.num_prefix_field.getText() or ""
            try:
                digits = int(self.num_digits_field.getText())
            except Exception:
                digits = NUMBER_DIGITS_DEFAULT
            try:
                start = int(self.num_start_field.getText())
            except Exception:
                start = 1
            return prefix, digits, start

        def _on_number_all(self, event):
            import threading
            t = threading.Thread(target=self._number_all_worker)
            t.daemon = True
            t.start()

        def _number_all_worker(self):
            prefix, digits, start = self._get_numbering_params()
            rx = numbering_regex(prefix)
            history = self._callbacks.getProxyHistory()
            count = 0
            for i, item in enumerate(history):
                no = start + i
                try:
                    old = item.getComment() or ""
                    if rx.match(old):
                        continue  # 既に採番済み（冪等）
                    token = numbering_token(prefix, digits, no)
                    item.setComment(token + old)
                    count += 1
                except Exception as e:
                    self._log(u"item#%d 採番エラー: %s" % (i + 1, str(e)))
            self._log(u"採番完了: %d 件（既採番はスキップ）" % count)

        def _on_number_clear_all(self, event):
            import threading
            t = threading.Thread(target=self._number_clear_all_worker)
            t.daemon = True
            t.start()

        def _number_clear_all_worker(self):
            prefix, digits, start = self._get_numbering_params()
            rx = numbering_regex(prefix)
            history = self._callbacks.getProxyHistory()
            count = 0
            for item in history:
                try:
                    old = item.getComment() or ""
                    if rx.match(old):
                        item.setComment(rx.sub("", old, count=1))
                        count += 1
                except Exception as e:
                    self._log(u"採番解除エラー: %s" % str(e))
            self._log(u"採番解除完了: %d 件" % count)

        def _on_clear_all_brackets(self, event):
            """HTTP history 全件の Comment から [ ... ] 形式の部分をすべて削除する。
            採番トークンや解析マーカーに限らず、ユーザーが手動で入れた [ ] のメモも
            区別なく削除される広範囲な操作のため、実行前に確認ダイアログを出す。"""
            ret = JOptionPane.showConfirmDialog(
                self.main_panel,
                u"HTTP history 全件の Comment から、[ ... ] で囲まれた部分をすべて削除します。\n"
                u"（このツールが書いた採番/解析マーカーだけでなく、ご自身が手動で\n"
                u"　[ ] を使って書いたメモがあれば、それも一緒に削除されます）\n\n"
                u"この操作は元に戻せません。実行しますか？",
                u"追加コメント全クリアの確認",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE)
            if ret != JOptionPane.YES_OPTION:
                self._log(u"追加コメント全クリアをキャンセルしました。")
                return
            import threading
            t = threading.Thread(target=self._clear_all_brackets_worker)
            t.daemon = True
            t.start()

        def _clear_all_brackets_worker(self):
            history = self._callbacks.getProxyHistory()
            count = 0
            for item in history:
                try:
                    old = item.getComment() or ""
                    if not old:
                        continue
                    new = strip_all_brackets(old)
                    if new != old:
                        item.setComment(new)
                        count += 1
                except Exception as e:
                    self._log(u"追加コメント全クリアエラー: %s" % str(e))
            self._log(u"追加コメント全クリア完了: %d 件のCommentを更新しました" % count)

        def _number_selected(self, selected_items):
            """右クリックメニューからの選択パケット採番。全history中の位置(No)で番号を決める。"""
            prefix, digits, start = self._get_numbering_params()
            rx = numbering_regex(prefix)
            history = self._callbacks.getProxyHistory()
            no_by_identity = {}
            for i, item in enumerate(history):
                try:
                    req = item.getRequest()
                    svc = item.getHttpService()
                    req_str = self._helpers.bytesToString(req) if req is not None else ""
                    host = svc.getHost() if svc else ""
                    port = svc.getPort() if svc else 0
                    proto = svc.getProtocol() if svc else ""
                    no_by_identity[(host, port, proto, req_str)] = start + i
                except Exception:
                    continue

            count = 0
            for item in selected_items:
                try:
                    req = item.getRequest()
                    svc = item.getHttpService()
                    req_str = self._helpers.bytesToString(req) if req is not None else ""
                    host = svc.getHost() if svc else ""
                    port = svc.getPort() if svc else 0
                    proto = svc.getProtocol() if svc else ""
                    key = (host, port, proto, req_str)
                    no = no_by_identity.get(key)
                    if no is None:
                        continue
                    old = item.getComment() or ""
                    if rx.match(old):
                        continue
                    token = numbering_token(prefix, digits, no)
                    item.setComment(token + old)
                    count += 1
                except Exception as e:
                    self._log(u"選択採番エラー: %s" % str(e))
            self._log(u"選択採番完了: %d 件" % count)

        # --- 集約色タブ ---
        def _build_color_panel(self):
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

            row1 = JPanel(FlowLayout(FlowLayout.LEFT))
            row1.add(JLabel(u"予約色（ご自身の色分けでは使わない色を選んでください）:"))
            self.color_combo = JComboBox(BURP_HIGHLIGHT_COLORS)
            self.color_combo.setSelectedItem(self.reserved_color)
            self.color_combo.addActionListener(self._on_color_changed)
            row1.add(self.color_combo)
            panel.add(row1)

            row2 = JPanel(FlowLayout(FlowLayout.LEFT))
            btn_apply = JButton(u"集約対象に予約色を適用（オンデマンド）", actionPerformed=self._on_apply_agg_color)
            btn_clear = JButton(u"予約色のみクリア", actionPerformed=self._on_clear_agg_color)
            row2.add(btn_apply)
            row2.add(btn_clear)
            panel.add(row2)

            note = JTextArea(
                u"注記:\n"
                u"・[解析更新] を先に実行してから使用してください。\n"
                u"・「予約色を適用」は、集約グループ内の『代表』以外（=集約対象）のパケットにのみ、\n"
                u"　選択した予約色を setHighlight します。ボタンを押した時だけ実行され、自動では動きません。\n"
                u"・「予約色のみクリア」は、現在の色が予約色になっているパケットのハイライトだけを解除します。\n"
                u"　ご自身が付けた別の色（例: 赤=重大 等）には一切触れません。\n"
                u"・自分の色分け作業と衝突しないよう、予約色は他の用途で使っていない色を選んでください。")
            note.setEditable(False)
            note.setOpaque(False)
            panel.add(note)
            return panel

        def _on_color_changed(self, event):
            self.reserved_color = str(self.color_combo.getSelectedItem())

        def _on_apply_agg_color(self, event):
            import threading
            t = threading.Thread(target=self._apply_agg_color_worker)
            t.daemon = True
            t.start()

        def _apply_agg_color_worker(self):
            if not self._packets_cache_exists():
                self._log(u"先に [解析] タブで [解析更新] を実行してください。")
                return
            history = self._callbacks.getProxyHistory()
            color = self.reserved_color
            count = 0
            for item in history:
                try:
                    req = item.getRequest()
                    svc = item.getHttpService()
                    req_str = self._helpers.bytesToString(req) if req is not None else ""
                    host = svc.getHost() if svc else ""
                    port = svc.getPort() if svc else 0
                    proto = svc.getProtocol() if svc else ""
                    key = (host, port, proto, req_str)
                    pkt = self.index_by_identity.get(key)
                    if pkt is None:
                        continue
                    if pkt.agg_role == u"集約対象":
                        item.setHighlight(color)
                        count += 1
                except Exception as e:
                    self._log(u"色適用エラー: %s" % str(e))
            self._log(u"集約対象に予約色(%s)を適用しました: %d 件" % (color, count))

        def _on_clear_agg_color(self, event):
            import threading
            t = threading.Thread(target=self._clear_agg_color_worker)
            t.daemon = True
            t.start()

        def _clear_agg_color_worker(self):
            history = self._callbacks.getProxyHistory()
            color = self.reserved_color
            count = 0
            for item in history:
                try:
                    if item.getHighlight() == color:
                        item.setHighlight(None)
                        count += 1
                except Exception as e:
                    self._log(u"色クリアエラー: %s" % str(e))
            self._log(u"予約色(%s)のみクリアしました: %d 件" % (color, count))

        def _packets_cache_exists(self):
            return hasattr(self, "_packets_cache") and self._packets_cache

        def _build_comment_by_vuln(self):
            """word.csv の comment 列（あれば）を Vuln-No で引けるようにした辞書を作る。
            ワード照合一覧の「ルールComment」列表示と、Commentへの追記（format_sf_marker）の
            両方から共通で使い、表示内容が食い違わないようにする。
            同じVuln-Noが複数ルールにまたがる場合は最後に読み込んだものが優先される
            （リクエスト用→レスポンス用の順で処理するため、両方に同じVuln-Noがあれば
            レスポンス用のcommentが優先される）。"""
            comment_by_vuln = {}
            for r in self.rules_request:
                c = r.get("comment", "")
                if c:
                    comment_by_vuln[r["vuln_no"]] = c
            for r in self.rules_response:
                c = r.get("comment", "")
                if c:
                    comment_by_vuln[r["vuln_no"]] = c
            return comment_by_vuln

        # ------------------------------------------------------------------------
        # Aura診断タブ（能動送信）
        # ------------------------------------------------------------------------
        # これまでの全タブと異なり、本タブは実際にHTTPリクエストを対象ホストへ送信する
        # （Google/Mandiant aura-inspector 相当の偵察・データ抽出）。すべての送信は
        # _aura_send_actions / _aura_http_get の2箇所に集約し、送信前ログ・エラー処理を
        # 一箇所で担保する。「アクティブ送信を有効にする」チェックが入るまで、送信系の
        # ボタンはすべて無効化される（self._aura_active_buttons に登録されたボタン）。

        def _build_aura_audit_panel(self):
            self._aura_active_buttons = []
            panel = JPanel(BorderLayout())
            tabs = JTabbedPane()
            tabs.addTab(u"① ターゲット設定", self._build_aura_target_section())
            tabs.addTab(u"② 偵察", self._build_aura_recon_section())
            tabs.addTab(u"③ データ抽出", self._build_aura_extract_section())
            panel.add(tabs, BorderLayout.CENTER)

            note = JTextArea(
                u"注記: このタブはこれまでの他タブと異なり、実際にHTTPリクエストを対象ホストへ"
                u"送信します。認可された脆弱性診断対象に対してのみ使用してください。詳細は"
                u"README/マニュアルの「Aura診断 タブ」および「安全上の注意」を参照してください。")
            note.setEditable(False)
            note.setLineWrap(True)
            note.setWrapStyleWord(True)
            note.setRows(3)
            note.setBackground(panel.getBackground())
            panel.add(note, BorderLayout.SOUTH)

            for b in self._aura_active_buttons:
                b.setEnabled(False)
            return panel

        def _build_aura_target_section(self):
            panel = JPanel()
            panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))

            arm_row = JPanel(FlowLayout(FlowLayout.LEFT))
            self.aura_arm_chk = JCheckBox(
                u"アクティブ送信を有効にする（対象ホストへ実際にHTTPリクエストを送信します）", False)
            self.aura_arm_chk.addActionListener(self._on_aura_arm_toggle)
            arm_row.add(self.aura_arm_chk)
            panel.add(arm_row)

            target_row = JPanel(FlowLayout(FlowLayout.LEFT))
            self.aura_target_label = JLabel(u"現在の対象: (未設定)")
            self.aura_target_label.setOpaque(True)
            self.aura_target_label.setBackground(Color(255, 230, 150))
            self.aura_target_label.setFont(Font("Dialog", Font.BOLD, 13))
            target_row.add(self.aura_target_label)
            target_row.add(JButton(u"ゲスト化（Cookieを外す）", actionPerformed=self._on_aura_force_guest))
            panel.add(target_row)

            hint2 = JTextArea(
                u"「ゲスト化」: 認証済みユーザーのパケットを対象に設定した場合でも、Cookieを送信対象から外し\n"
                u"aura.tokenを既定値にリセットすることで、以降の②③を未認証(ゲスト)として実行できます\n"
                u"（Salesforceのユーザー認証はCookie=セッションIDが担っているため、これを外すだけでゲスト相当になります）。")
            hint2.setEditable(False)
            hint2.setRows(3)
            hint2.setBackground(panel.getBackground())
            panel.add(hint2)

            cand_row = JPanel(FlowLayout(FlowLayout.LEFT))
            cand_row.add(JLabel(u"候補パケット（[解析更新]済みのAura SPA通信）:"))
            self.aura_candidate_combo = JComboBox([])
            self.aura_candidate_combo.setPreferredSize(Dimension(480, 24))
            cand_row.add(self.aura_candidate_combo)
            cand_row.add(JButton(u"候補を更新", actionPerformed=self._on_aura_reload_candidates))
            cand_row.add(JButton(u"選択パケットから読込", actionPerformed=self._on_aura_load_from_selected))
            panel.add(cand_row)

            hint = JTextArea(
                u"推奨: Proxy history上でAuraリクエストを右クリック →\n"
                u"「SF Helper: このパケットをAura診断対象に設定」でも設定できます\n"
                u"（[解析更新]の実行有無に関わらず使えます）。")
            hint.setEditable(False)
            hint.setRows(3)
            hint.setBackground(panel.getBackground())
            panel.add(hint)

            manual_panel = JPanel()
            manual_panel.setLayout(BoxLayout(manual_panel, BoxLayout.Y_AXIS))
            manual_panel.setBorder(BorderFactory.createTitledBorder(
                u"手動設定（コールドスタート用: まだ何も捕捉していないゲスト対象を診断する場合など）"))

            row_url = JPanel(FlowLayout(FlowLayout.LEFT))
            row_url.add(JLabel(u"Base URL:"))
            self.aura_manual_url_field = JTextField(u"https://example.my.salesforce.com", 30)
            row_url.add(self.aura_manual_url_field)
            manual_panel.add(row_url)

            row_ep = JPanel(FlowLayout(FlowLayout.LEFT))
            row_ep.add(JLabel(u"Auraエンドポイントパス:"))
            self.aura_manual_endpoint_field = JTextField(u"/s/sfsites/aura", 18)
            row_ep.add(self.aura_manual_endpoint_field)
            btn_detect = JButton(u"Auraエンドポイント自動検出", actionPerformed=self._on_aura_detect_endpoint)
            self._aura_active_buttons.append(btn_detect)
            row_ep.add(btn_detect)
            manual_panel.add(row_ep)

            row_app = JPanel(FlowLayout(FlowLayout.LEFT))
            row_app.add(JLabel(u"Appパス（任意。空欄なら自動推定）:"))
            self.aura_manual_app_field = JTextField(u"", 15)
            row_app.add(self.aura_manual_app_field)
            manual_panel.add(row_app)

            manual_panel.add(JLabel(u"aura.context (JSON。空欄ならダミー値を使用):"))
            self.aura_manual_context_area = JTextArea(3, 60)
            manual_panel.add(JScrollPane(self.aura_manual_context_area))

            row_tok = JPanel(FlowLayout(FlowLayout.LEFT))
            row_tok.add(JLabel(u"aura.token（空欄ならゲスト想定）:"))
            self.aura_manual_token_field = JTextField(u"", 40)
            row_tok.add(self.aura_manual_token_field)
            manual_panel.add(row_tok)

            manual_panel.add(JLabel(u"Cookieヘッダー（例: sid=00Dxx...; 任意）:"))
            self.aura_manual_cookie_field = JTextField(u"", 60)
            manual_panel.add(self.aura_manual_cookie_field)

            row_apply = JPanel(FlowLayout(FlowLayout.LEFT))
            row_apply.add(JButton(u"適用（手動設定を対象にする）", actionPerformed=self._on_aura_manual_apply))
            manual_panel.add(row_apply)

            panel.add(manual_panel)
            return panel

        def _build_aura_recon_section(self):
            panel = JPanel(BorderLayout())
            top = JPanel()
            top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))

            chk_row1 = JPanel(FlowLayout(FlowLayout.LEFT))
            chk_row1.add(JLabel(u"実行する調査項目（どこまで調査するかを調整できます）:"))
            top.add(chk_row1)
            chk_row2 = JPanel(FlowLayout(FlowLayout.LEFT))
            self.aura_recon_chk_objects = JCheckBox(u"オブジェクト一覧取得", True)
            self.aura_recon_chk_counts = JCheckBox(u"各オブジェクトの件数取得", True)
            self.aura_recon_chk_uilist = JCheckBox(u"Record List UI検出", True)
            self.aura_recon_chk_homeurl = JCheckBox(u"Home URL検出", True)
            self.aura_recon_chk_selfreg = JCheckBox(u"自己登録確認", True)
            self.aura_recon_chk_graphql = JCheckBox(u"GraphQL可用性確認", True)
            self.aura_recon_chk_controllers = JCheckBox(u"カスタムコントローラ抽出", True)
            for c in (self.aura_recon_chk_objects, self.aura_recon_chk_counts, self.aura_recon_chk_uilist,
                      self.aura_recon_chk_homeurl, self.aura_recon_chk_selfreg, self.aura_recon_chk_graphql,
                      self.aura_recon_chk_controllers):
                chk_row2.add(c)
            top.add(chk_row2)
            note = JTextArea(
                u"「各オブジェクトの件数取得」「Record List UI検出」は「オブジェクト一覧取得」の"
                u"結果が必要なため、これらのみチェックした場合も内部的にオブジェクト一覧取得を"
                u"併せて実行します。件数・UI検出はオブジェクト数分のリクエストが発生する点に注意してください。")
            note.setEditable(False)
            note.setLineWrap(True)
            note.setWrapStyleWord(True)
            note.setRows(2)
            note.setBackground(panel.getBackground())
            top.add(note)

            run_row = JPanel(FlowLayout(FlowLayout.LEFT))
            btn_recon = JButton(u"偵察を実行", actionPerformed=self._on_aura_recon_run)
            self._aura_active_buttons.append(btn_recon)
            run_row.add(btn_recon)
            self.aura_recon_status = JLabel(u"未実行")
            run_row.add(self.aura_recon_status)
            run_row.add(JButton(u"偵察結果をCSV出力...", actionPerformed=self._on_aura_export_recon_csv))
            run_row.add(JButton(u"偵察結果をJSON出力...", actionPerformed=self._on_aura_export_recon_json))
            top.add(run_row)

            panel.add(top, BorderLayout.NORTH)

            tables_panel = JPanel()
            tables_panel.setLayout(BoxLayout(tables_panel, BoxLayout.Y_AXIS))

            tables_panel.add(JLabel(u"オブジェクト一覧（列見出しクリックでソート可）"))
            self.aura_objects_table_model = DefaultTableModel(
                [], [u"オブジェクトAPI名", u"KeyPrefix", u"件数(totalCount)", u"一覧UI検出", u"備考"])
            self.aura_objects_table = JTable(self.aura_objects_table_model)
            self.aura_objects_table.setAutoCreateRowSorter(True)
            self.aura_objects_table.getRowSorter().setComparator(2, _NoneLastIntComparator())
            objects_scroll = JScrollPane(self.aura_objects_table)
            objects_scroll.setPreferredSize(Dimension(900, 180))
            tables_panel.add(objects_scroll)

            tables_panel.add(JLabel(u"ホームURL一覧"))
            self.aura_homeurls_table_model = DefaultTableModel([], [u"オブジェクトAPI名", u"Home URL"])
            self.aura_homeurls_table = JTable(self.aura_homeurls_table_model)
            self.aura_homeurls_table.setAutoCreateRowSorter(True)
            homeurls_scroll = JScrollPane(self.aura_homeurls_table)
            homeurls_scroll.setPreferredSize(Dimension(900, 100))
            tables_panel.add(homeurls_scroll)

            tables_panel.add(JLabel(u"カスタムコントローラ一覧"))
            self.aura_controllers_table_model = DefaultTableModel([], [u"Apexコントローラ/アクション", u"検出元URL"])
            self.aura_controllers_table = JTable(self.aura_controllers_table_model)
            self.aura_controllers_table.setAutoCreateRowSorter(True)
            controllers_scroll = JScrollPane(self.aura_controllers_table)
            controllers_scroll.setPreferredSize(Dimension(900, 100))
            tables_panel.add(controllers_scroll)

            tables_panel.add(JLabel(u"その他チェック結果"))
            self.aura_checks_table_model = DefaultTableModel([], [u"チェック項目", u"結果"])
            self.aura_checks_table = JTable(self.aura_checks_table_model)
            self.aura_checks_table.setAutoCreateRowSorter(True)
            checks_scroll = JScrollPane(self.aura_checks_table)
            checks_scroll.setPreferredSize(Dimension(900, 120))
            tables_panel.add(checks_scroll)

            panel.add(JScrollPane(tables_panel), BorderLayout.CENTER)
            return panel

        def _build_aura_extract_section(self):
            panel = JPanel(BorderLayout())
            top = JPanel()
            top.setLayout(BoxLayout(top, BoxLayout.Y_AXIS))

            list_row = JPanel(BorderLayout())
            list_row.add(JLabel(u"対象オブジェクト（②偵察の結果から選択。複数選択可・列見出しクリックでソート可）"),
                         BorderLayout.NORTH)
            self.aura_extract_object_table_model = DefaultTableModel(
                [], [u"オブジェクトAPI名", u"KeyPrefix", u"件数(totalCount)", u"一覧UI検出", u"備考"])
            self.aura_extract_object_table = JTable(self.aura_extract_object_table_model)
            self.aura_extract_object_table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
            self.aura_extract_object_table.setAutoCreateRowSorter(True)
            self.aura_extract_object_table.getRowSorter().setComparator(2, _NoneLastIntComparator())
            list_scroll = JScrollPane(self.aura_extract_object_table)
            list_scroll.setPreferredSize(Dimension(900, 180))
            list_row.add(list_scroll, BorderLayout.CENTER)
            list_btns = JPanel(FlowLayout(FlowLayout.LEFT))
            list_btns.add(JButton(u"全選択", actionPerformed=self._on_aura_select_all_objects))
            list_btns.add(JButton(u"選択解除", actionPerformed=self._on_aura_clear_object_selection))
            list_row.add(list_btns, BorderLayout.SOUTH)
            top.add(list_row)

            opts_row = JPanel(FlowLayout(FlowLayout.LEFT))
            opts_row.add(JLabel(u"1オブジェクトあたりの取得上限（どこまで収集するかを調整できます）:"))
            self.aura_row_cap_field = JTextField(u"5000", 8)
            opts_row.add(self.aura_row_cap_field)
            opts_row.add(JLabel(u"件 / リクエスト間隔:"))
            self.aura_delay_field = JTextField(u"200", 6)
            opts_row.add(self.aura_delay_field)
            opts_row.add(JLabel(u"ms"))
            top.add(opts_row)

            run_row = JPanel(FlowLayout(FlowLayout.LEFT))
            btn_extract_run = JButton(u"抽出実行", actionPerformed=self._on_aura_extract_run)
            self._aura_active_buttons.append(btn_extract_run)
            run_row.add(btn_extract_run)
            self.aura_extract_status = JLabel(u"未実行")
            run_row.add(self.aura_extract_status)
            top.add(run_row)

            panel.add(top, BorderLayout.NORTH)

            self.aura_extract_table_model = DefaultTableModel(
                [], [u"オブジェクトAPI名", u"状態", u"取得件数", u"手法", u"備考"])
            self.aura_extract_table = JTable(self.aura_extract_table_model)
            self.aura_extract_table.setAutoCreateRowSorter(True)
            self.aura_extract_table.getRowSorter().setComparator(2, _NoneLastIntComparator())
            panel.add(JScrollPane(self.aura_extract_table), BorderLayout.CENTER)

            export_row = JPanel(FlowLayout(FlowLayout.LEFT))
            export_row.add(JButton(u"CSV出力...", actionPerformed=self._on_aura_export_csv))
            export_row.add(JButton(u"JSON出力...", actionPerformed=self._on_aura_export_json))
            panel.add(export_row, BorderLayout.SOUTH)
            return panel

        # --- ターゲット設定 ---

        def _on_aura_arm_toggle(self, event):
            armed = self.aura_arm_chk.isSelected()
            for b in getattr(self, "_aura_active_buttons", []):
                b.setEnabled(armed)
            if armed:
                self._log(u"Aura診断: アクティブ送信を有効にしました。対象ホストへ実際にHTTPリクエストを"
                          u"送信します。認可された診断対象であることを必ず確認してください。")
            else:
                self._log(u"Aura診断: アクティブ送信を無効にしました。")

        def _update_aura_target_label(self):
            def do_update():
                if self._aura_session:
                    s = self._aura_session
                    mode = u"認証あり(Cookie送信)" if s.get("cookie_header") else u"ゲスト(Cookie未送信)"
                    self.aura_target_label.setText(
                        u"現在の対象: %s://%s:%s%s　｜　%s"
                        % (s["protocol"], s["host"], s["port"], s.get("aura_endpoint_path", u""), mode))
                else:
                    self.aura_target_label.setText(u"現在の対象: (未設定)")
            SwingUtilities.invokeLater(do_update)

        def _on_aura_force_guest(self, event):
            """認証済みユーザーのパケットを対象に設定していても、Cookieを送信対象から外し
            aura.tokenを既定値(undefined)にリセットすることで、以降の送信を未認証(ゲスト)化する。
            Salesforceの実際のユーザー認証はCookie(セッションID)が担っており、aura.tokenは
            Auraフレームワーク側の検証トークンに過ぎないため、Cookieを外すだけでゲスト相当になる。"""
            if not self._aura_session:
                self._log(u"Aura診断: 先に対象を設定してください。")
                return
            self._aura_session["cookie_header"] = u""
            self._aura_session["aura_token"] = u"undefined"
            self._update_aura_target_label()
            self._log(u"Aura診断: 対象をゲスト化しました（Cookie未送信・aura.tokenを既定値にリセット）。"
                      u"以降の②偵察・③データ抽出は未認証として実行されます。")

        def _aura_derive_app_path(self, aura_endpoint_path, manual_app_path=None):
            if manual_app_path:
                return manual_app_path
            ep = aura_endpoint_path or u""
            for marker in AURA_ENDPOINT_PATH_CANDIDATES:
                if ep.endswith(marker):
                    prefix = ep[:len(ep) - len(marker)]
                    return (prefix + u"/s") if prefix else u"/s"
            return u"/"

        def _on_aura_reload_candidates(self, event):
            self.aura_candidate_combo.removeAllItems()
            if not self._packets_cache_exists():
                self._log(u"Aura診断: 候補パケットがありません。先に[解析]タブで[解析更新]を実行してください。")
                return
            self._aura_candidates = []
            for pkt in self._packets_cache:
                if pkt.cls_code != CLS_SPA:
                    continue
                label = u"%s %s %s" % (pkt.comment or u"(no comment)", pkt.method, pkt.url)
                self.aura_candidate_combo.addItem(safe_text(label))
                self._aura_candidates.append(pkt)
            self._log(u"Aura診断: 候補パケット %d 件を読み込みました。" % len(self._aura_candidates))

        def _on_aura_load_from_selected(self, event):
            idx = self.aura_candidate_combo.getSelectedIndex()
            candidates = getattr(self, "_aura_candidates", None)
            if idx < 0 or not candidates or idx >= len(candidates):
                self._log(u"Aura診断: 候補パケットを選択してください。")
                return
            pkt = candidates[idx]
            history = self._callbacks.getProxyHistory()
            item = None
            for h in history:
                try:
                    req = h.getRequest()
                    svc = h.getHttpService()
                    req_str = self._helpers.bytesToString(req) if req is not None else u""
                    host = svc.getHost() if svc else u""
                    port = svc.getPort() if svc else 0
                    proto = svc.getProtocol() if svc else u""
                    if (host, port, proto, req_str) == pkt.identity:
                        item = h
                        break
                except Exception:
                    continue
            if item is None:
                self._log(u"Aura診断: 選択パケットが現在のhistoryに見つかりませんでした。")
                return
            self._set_aura_target_from_selected([item])

        def _set_aura_target_from_selected(self, selected_items):
            """右クリック「このパケットをAura診断対象に設定」、および[Aura診断]タブの
            「選択パケットから読込」の両方から呼ばれる共通処理。選択された最初のパケットの
            生リクエストから host/port/protocol と、その場で有効な aura.context/aura.token を
            直接読み取り、self._aura_session を更新する（fwuidをHTMLスクレイピングで
            再発見する必要がない——実際にキャプチャされたリクエストは既に有効なセッションを
            持っているため）。"""
            if not selected_items:
                return
            item = selected_items[0]
            if len(selected_items) > 1:
                self._log(u"Aura診断: 複数選択されていますが、先頭の1件を対象にします。")
            try:
                req = item.getRequest()
                svc = item.getHttpService()
                if req is None or svc is None:
                    self._log(u"Aura診断: 選択パケットのリクエスト情報が取得できません。")
                    return
                req_info = self._helpers.analyzeRequest(svc, req)
                url = req_info.getUrl()
                path = url.getPath() if url is not None else u""
                path = path or u""
                req_headers = list(req_info.getHeaders())
                req_ctype = u""
                cookie_header = u""
                ua_header = u""
                for h in req_headers:
                    hl = h.lower()
                    if hl.startswith("content-type:"):
                        req_ctype = h.split(":", 1)[1].strip()
                    elif hl.startswith("cookie:"):
                        cookie_header = h
                    elif hl.startswith("user-agent:"):
                        ua_header = h
                body_offset = req_info.getBodyOffset()
                body_bytes = req[body_offset:]
                body_text = self._helpers.bytesToString(body_bytes)
                aura_context, aura_token = extract_aura_context_and_token(body_text, req_ctype)
                if not aura_context or not aura_token:
                    self._log(u"Aura診断: 選択パケットからaura.context/aura.tokenを取得できませんでした"
                              u"（Auraリクエストでない可能性があります）。")
                    return
                self._aura_session = {
                    "http_service": svc,
                    "host": svc.getHost(),
                    "port": svc.getPort(),
                    "protocol": svc.getProtocol(),
                    "aura_endpoint_path": path,
                    "app_path": self._aura_derive_app_path(path),
                    "cookie_header": cookie_header,
                    "user_agent_header": ua_header,
                    "aura_context": aura_context,
                    "aura_token": aura_token,
                }
                self._update_aura_target_label()
                self._log(u"Aura診断: 対象を設定しました: %s://%s:%s%s"
                          % (svc.getProtocol(), svc.getHost(), svc.getPort(), path))
            except Exception as e:
                self._log(u"Aura診断: 対象パケットの読み込みに失敗しました: %s" % safe_text(e))

        def _on_aura_manual_apply(self, event):
            url_text = (self.aura_manual_url_field.getText() or u"").strip()
            endpoint_path = (self.aura_manual_endpoint_field.getText() or u"").strip()
            manual_app = (self.aura_manual_app_field.getText() or u"").strip()
            context_text = (self.aura_manual_context_area.getText() or u"").strip()
            token_text = (self.aura_manual_token_field.getText() or u"").strip()
            cookie_text = (self.aura_manual_cookie_field.getText() or u"").strip()
            if not url_text or not endpoint_path:
                self._log(u"Aura診断: Base URLとAuraエンドポイントパスを入力してください。")
                return
            m = re.match(r'^(https?)://([^/:]+)(?::(\d+))?', url_text)
            if not m:
                self._log(u"Aura診断: Base URLの形式が正しくありません（例: https://foo.my.salesforce.com）。")
                return
            try:
                protocol = m.group(1)
                host = m.group(2)
                port = int(m.group(3)) if m.group(3) else (443 if protocol == "https" else 80)
                svc = self._helpers.buildHttpService(host, port, protocol)
                aura_context = context_text or build_aura_context_json(u"INVALID", u"siteforce:loginApp2")
                aura_token = token_text or u"undefined"
                self._aura_session = {
                    "http_service": svc,
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "aura_endpoint_path": endpoint_path,
                    "app_path": self._aura_derive_app_path(endpoint_path, manual_app),
                    "cookie_header": (u"Cookie: %s" % cookie_text) if cookie_text else u"",
                    "user_agent_header": u"",
                    "aura_context": aura_context,
                    "aura_token": aura_token,
                }
                self._update_aura_target_label()
                self._log(u"Aura診断: 手動設定を対象に適用しました: %s://%s:%s%s"
                          % (protocol, host, port, endpoint_path))
            except Exception as e:
                self._log(u"Aura診断: 手動設定の適用に失敗しました: %s" % safe_text(e))

        def _on_aura_detect_endpoint(self, event):
            url_text = (self.aura_manual_url_field.getText() or u"").strip()
            if not url_text:
                self._log(u"Aura診断: Base URLを入力してください。")
                return
            import threading
            t = threading.Thread(target=self._aura_detect_endpoint_worker, args=(url_text,))
            t.daemon = True
            t.start()

        def _aura_detect_endpoint_worker(self, url_text):
            try:
                m = re.match(r'^(https?)://([^/:]+)(?::(\d+))?', url_text)
                if not m:
                    self._log(u"Aura診断: Base URLの形式が正しくありません。")
                    return
                protocol = m.group(1)
                host = m.group(2)
                port = int(m.group(3)) if m.group(3) else (443 if protocol == "https" else 80)
                svc = self._helpers.buildHttpService(host, port, protocol)
                dummy_action = build_aura_action(
                    u"242;a",
                    u"serviceComponent://ui.force.components.controllers.relatedList."
                    u"RelatedListContainerDataProviderController/ACTION$getRecords",
                    {"recordId": "Foobar"})
                dummy_context = build_aura_context_json(u"INVALID", u"siteforce:loginApp2")
                body = build_aura_post_body(build_aura_message_json([dummy_action]), dummy_context, u"undefined")
                for path in AURA_ENDPOINT_PATH_CANDIDATES:
                    self._log(u"Aura診断: エンドポイント候補を確認中: %s%s" % (host, path))
                    headers = [u"POST %s HTTP/1.1" % path, u"Host: %s" % host,
                               u"User-Agent: %s" % AURA_DEFAULT_USER_AGENT,
                               u"Content-Type: application/x-www-form-urlencoded;charset=UTF-8",
                               u"Accept: application/json"]
                    req_bytes = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(body))
                    try:
                        resp_item = self._callbacks.makeHttpRequest(svc, req_bytes)
                    except Exception as e:
                        self._log(u"Aura診断: %s への送信に失敗: %s" % (safe_text(path), safe_text(e)))
                        continue
                    resp_bytes = resp_item.getResponse()
                    if resp_bytes is None:
                        continue
                    resp_info = self._helpers.analyzeResponse(resp_bytes)
                    resp_text = self._helpers.bytesToString(resp_bytes[resp_info.getBodyOffset():])
                    if looks_like_valid_aura_endpoint_response(resp_text):
                        def do_update(p=path):
                            self.aura_manual_endpoint_field.setText(p)
                        SwingUtilities.invokeLater(do_update)
                        self._log(u"Aura診断: Auraエンドポイントを検出しました: %s" % path)
                        token_guess = parse_aura_token_from_text(resp_text)
                        if token_guess:
                            def do_token(t=token_guess):
                                self.aura_manual_token_field.setText(t)
                            SwingUtilities.invokeLater(do_token)
                            self._log(u"Aura診断: 応答からトークンらしき文字列を検出し、"
                                      u"自動入力しました（要確認）。")
                        return
                self._log(u"Aura診断: どの候補パスでもAuraエンドポイントを検出できませんでした。")
            except Exception as e:
                self._log(u"Aura診断: エンドポイント検出中にエラー: %s" % safe_text(e))

        # --- ネットワーキングの一元化 ---

        def _aura_send_actions(self, actions):
            """Aura診断機能の唯一のAuraアクション送信口。self._aura_sessionに基づきPOSTを
            組み立て、callbacks.makeHttpRequestで送信する。すべての呼び出し元（偵察・抽出の
            各ワーカー）は必ずこのメソッドを経由すること（送信前ログ・エラー処理を一箇所に
            集約するため）。戻り値: (resp_item, parsed_json_or_None, raw_resp_text)。
            通信エラー時は (None, None, u"") を返し、例外は外に投げない。"""
            session = self._aura_session
            if not session:
                self._log(u"Aura診断: 対象が未設定です。")
                return None, None, u""
            try:
                message_json = build_aura_message_json(actions)
                body = build_aura_post_body(message_json, session["aura_context"], session["aura_token"])
                headers = [
                    u"POST %s HTTP/1.1" % session["aura_endpoint_path"],
                    u"Host: %s" % session["host"],
                    session.get("user_agent_header") or (u"User-Agent: %s" % AURA_DEFAULT_USER_AGENT),
                    u"Content-Type: application/x-www-form-urlencoded;charset=UTF-8",
                    u"Accept: application/json",
                ]
                if session.get("cookie_header"):
                    headers.append(session["cookie_header"])
                req_bytes = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(body))
                self._log(u"Aura診断: -> POST %s%s (%d actions)"
                          % (session["host"], session["aura_endpoint_path"], len(actions)))
                resp_item = self._callbacks.makeHttpRequest(session["http_service"], req_bytes)
                resp_bytes = resp_item.getResponse()
                if resp_bytes is None:
                    self._log(u"Aura診断: 応答がありませんでした。")
                    return resp_item, None, u""
                resp_info = self._helpers.analyzeResponse(resp_bytes)
                resp_text = self._helpers.bytesToString(resp_bytes[resp_info.getBodyOffset():])
                resp_json = parse_aura_response_json(resp_text)
                if resp_json is None:
                    self._log(u"Aura診断: 非JSON応答（先頭200文字）: %s"
                              % safe_text(flatten_for_csv(resp_text, 200)))
                return resp_item, resp_json, resp_text
            except Exception as e:
                self._log(u"Aura診断: 通信エラー: %s" % safe_text(e))
                return None, None, u""

        def _aura_http_get(self, path_or_url):
            """通常のHTTP GETを送信する（Auraアクションではない、リソース取得用。
            カスタムコントローラ抽出で、アプリのルートページやJS/コンポーネント定義を
            フェッチするために使う）。path_or_urlが絶対URLならホスト部を解析し、
            そうでなければ現在のAuraセッションのホストに対する相対パスとして扱う。"""
            session = self._aura_session
            if not session:
                return u""
            try:
                if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
                    m = re.match(r'^(https?)://([^/]+)(/.*)?$', path_or_url)
                    if not m:
                        return u""
                    protocol = m.group(1)
                    host_port = m.group(2)
                    path = m.group(3) or u"/"
                    if ":" in host_port:
                        host, port_s = host_port.split(":", 1)
                        port = int(port_s)
                    else:
                        host = host_port
                        port = 443 if protocol == "https" else 80
                    svc = self._helpers.buildHttpService(host, port, protocol)
                else:
                    svc = session["http_service"]
                    host = session["host"]
                    path = path_or_url if path_or_url.startswith("/") else (u"/" + path_or_url)
                headers = [u"GET %s HTTP/1.1" % path, u"Host: %s" % host,
                           session.get("user_agent_header") or (u"User-Agent: %s" % AURA_DEFAULT_USER_AGENT),
                           u"Accept: */*"]
                if session.get("cookie_header"):
                    headers.append(session["cookie_header"])
                req_bytes = self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(u""))
                self._log(u"Aura診断: -> GET %s%s" % (host, path))
                resp_item = self._callbacks.makeHttpRequest(svc, req_bytes)
                resp_bytes = resp_item.getResponse()
                if resp_bytes is None:
                    return u""
                resp_info = self._helpers.analyzeResponse(resp_bytes)
                return self._helpers.bytesToString(resp_bytes[resp_info.getBodyOffset():])
            except Exception as e:
                self._log(u"Aura診断: GET通信エラー(%s): %s" % (safe_text(path_or_url), safe_text(e)))
                return u""

        def _looks_like_auth_error(self, text):
            if not text:
                return False
            low = text.lower()
            return any(marker in low for marker in AURA_AUTH_ERROR_MARKERS)

        # --- ② 偵察 ---

        def _on_aura_recon_run(self, event):
            if not self._aura_session:
                self._log(u"Aura診断: 先に対象を設定してください。")
                return
            if not self.aura_arm_chk.isSelected():
                self._log(u"Aura診断: 「アクティブ送信を有効にする」にチェックを入れてから実行してください。")
                return
            import threading
            t = threading.Thread(target=self._aura_recon_worker)
            t.daemon = True
            t.start()

        def _aura_discover_custom_controllers(self):
            """アプリのルートページと、そこから見つかるJS/コンポーネント定義リソースを取得し、
            カスタムApexコントローラ参照を抽出する（通常のブラウジングでは呼ばれない
            コントローラも、コンポーネント定義には静的に含まれるため発見できることがある）。"""
            session = self._aura_session
            app_path = session.get("app_path") or u"/"
            results = []
            html_text = self._aura_http_get(app_path)
            if not html_text:
                return results
            resource_urls = parse_resource_urls_from_html(html_text)
            seen = set()
            for res_url in resource_urls[:50]:  # 安全のため取得件数に上限を設ける
                if res_url in seen:
                    continue
                seen.add(res_url)
                text = self._aura_http_get(res_url)
                if not text:
                    continue
                for name in parse_apex_controller_names(text):
                    results.append((name, res_url))
            return results

        def _aura_recon_worker(self):
            self._log(u"Aura診断: 偵察を開始します。")
            try:
                run_objects = self.aura_recon_chk_objects.isSelected()
                run_counts = self.aura_recon_chk_counts.isSelected()
                run_uilist = self.aura_recon_chk_uilist.isSelected()
                run_homeurl = self.aura_recon_chk_homeurl.isSelected()
                run_selfreg = self.aura_recon_chk_selfreg.isSelected()
                run_graphql = self.aura_recon_chk_graphql.isSelected()
                run_controllers = self.aura_recon_chk_controllers.isSelected()

                checks = []
                object_names = []
                objects_rows = {}
                home_urls = {}
                custom_controllers = []
                gql_enabled = False

                if run_selfreg:
                    actions = build_selfreg_actions(u"selfreg_enabled", u"selfreg_url")
                    _, resp_json, _ = self._aura_send_actions(actions)
                    by_id = extract_action_responses_by_id(resp_json)
                    enabled, url = parse_selfreg_result(by_id.get(u"selfreg_enabled"), by_id.get(u"selfreg_url"))
                    checks.append((u"自己登録", (u"有効: %s" % safe_text(url)) if enabled else u"無効/不明"))

                if run_graphql:
                    _, resp_json, _ = self._aura_send_actions([build_graphql_availability_action(u"gql_check")])
                    by_id = extract_action_responses_by_id(resp_json)
                    gql_enabled = parse_graphql_availability_result(by_id.get(u"gql_check"))
                    checks.append((u"GraphQL利用可否", u"利用可能" if gql_enabled else u"利用不可/不明"))
                self._aura_recon_result["gql_enabled"] = gql_enabled

                need_objects = run_objects or run_counts or run_uilist
                if need_objects:
                    _, resp_json, _ = self._aura_send_actions([build_getconfigdata_action(u"cfg")])
                    by_id = extract_action_responses_by_id(resp_json)
                    objects_map, csp_trusted = parse_getconfigdata_result(by_id.get(u"cfg"))
                    checks.append((u"CSP信頼済みサイト数", str(len(csp_trusted))))
                    object_names = list(objects_map.keys())
                    self._log(u"Aura診断: %d 件のオブジェクトを検出しました。" % len(object_names))
                    for name in object_names:
                        objects_rows[name] = {"key_prefix": objects_map.get(name, u""),
                                               "count": None, "ui_list": None, "note": u""}

                if run_counts and object_names:
                    for chunk in chunk_actions(
                            [build_getitems_count_action(name, name) for name in object_names], 100):
                        _, resp_json, _ = self._aura_send_actions(chunk)
                        by_id = extract_action_responses_by_id(resp_json)
                        for name in [a["id"] for a in chunk]:
                            action_resp = by_id.get(name)
                            if action_resp is None:
                                objects_rows[name]["note"] = u"応答なし"
                                continue
                            if action_state(action_resp) == u"ERROR":
                                err = action_resp.get("error") or [{}]
                                objects_rows[name]["note"] = safe_text(
                                    err[0].get("message", u"エラー") if err else u"エラー")
                                continue
                            objects_rows[name]["count"] = parse_getitems_count_result(action_resp)

                if run_uilist and object_names:
                    objects_with_views = {}
                    for chunk in chunk_actions(
                            [build_listview_picker_action(name, name) for name in object_names], 100):
                        _, resp_json, _ = self._aura_send_actions(chunk)
                        by_id = extract_action_responses_by_id(resp_json)
                        for name in [a["id"] for a in chunk]:
                            filter_names = parse_listview_picker_result(by_id.get(name))
                            if filter_names:
                                objects_with_views[name] = filter_names[0]
                    items_actions = [build_listview_items_action(u"%s;lv" % name, name, filt)
                                      for name, filt in objects_with_views.items()]
                    ui_found_count = 0
                    for chunk in chunk_actions(items_actions, 100):
                        _, resp_json, _ = self._aura_send_actions(chunk)
                        by_id = extract_action_responses_by_id(resp_json)
                        for a in chunk:
                            name = a["id"].rsplit(";", 1)[0]
                            found = parse_listview_items_result(by_id.get(a["id"]))
                            objects_rows[name]["ui_list"] = found
                            if found:
                                ui_found_count += 1
                    self._log(u"Aura診断: Record List UIが検出されたオブジェクト: %d 件" % ui_found_count)

                if run_homeurl:
                    _, resp_json, _ = self._aura_send_actions([build_home_bootstrap_action(u"home")])
                    if resp_json:
                        raw_entry = None
                        for a in (resp_json.get("actions") or []):
                            if a.get("id") == u"home":
                                raw_entry = a
                                break
                        by_id = extract_action_responses_by_id(resp_json)
                        if raw_entry is not None and action_state(by_id.get(u"home")) == u"SUCCESS":
                            home_urls = parse_home_bootstrap_urls(raw_entry)
                    self._log(u"Aura診断: Home URL %d 件を検出しました。" % len(home_urls))

                if run_controllers:
                    try:
                        custom_controllers = self._aura_discover_custom_controllers()
                    except Exception as e:
                        self._log(u"Aura診断: カスタムコントローラ抽出でエラー: %s" % safe_text(e))

                self._aura_recon_result["objects"] = objects_rows
                self._aura_recon_result["object_names"] = object_names
                self._aura_recon_result["home_urls"] = home_urls
                self._aura_recon_result["custom_controllers"] = custom_controllers
                self._aura_recon_result["checks"] = checks

                def do_update():
                    self.aura_objects_table_model.setRowCount(0)
                    self.aura_extract_object_table_model.setRowCount(0)
                    for name in object_names:
                        row = objects_rows[name]
                        row_cells = [
                            name, row["key_prefix"],
                            row["count"],
                            (u"あり" if row["ui_list"] else (u"なし" if row["ui_list"] is not None else u"-")),
                            row["note"],
                        ]
                        self.aura_objects_table_model.addRow(row_cells)
                        # データ抽出タブの対象選択テーブルにも同じ内容を表示する（件数等を見て
                        # 抽出すべきか判断できるように、②偵察の結果をそのまま流用する）。
                        self.aura_extract_object_table_model.addRow(list(row_cells))
                    self.aura_homeurls_table_model.setRowCount(0)
                    for name, url in home_urls.items():
                        self.aura_homeurls_table_model.addRow([name, url])
                    self.aura_controllers_table_model.setRowCount(0)
                    for controller, src_url in custom_controllers:
                        self.aura_controllers_table_model.addRow([controller, src_url])
                    self.aura_checks_table_model.setRowCount(0)
                    for label, result in checks:
                        self.aura_checks_table_model.addRow([label, result])
                    self.aura_recon_status.setText(u"完了: オブジェクト%d件" % len(object_names))
                SwingUtilities.invokeLater(do_update)
                self._log(u"Aura診断: 偵察が完了しました。")
            except Exception as e:
                self._log(u"Aura診断: 偵察中にエラーが発生しました: %s" % safe_text(e))

        def _aura_recon_has_results(self):
            r = self._aura_recon_result
            return bool(r.get("object_names") or r.get("home_urls") or r.get("custom_controllers") or r.get("checks"))

        def _on_aura_export_recon_json(self, event):
            if not self._aura_recon_has_results():
                self._log(u"Aura診断: 先に偵察を実行してください。")
                return
            chooser = JFileChooser()
            chooser.setDialogTitle(u"偵察結果JSONの保存先を選択")
            chooser.setSelectedFile(File("aura_recon_result.json"))
            ret = chooser.showSaveDialog(self.main_panel)
            if ret != JFileChooser.APPROVE_OPTION:
                return
            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.lower().endswith(".json"):
                path += ".json"
            import threading
            t = threading.Thread(target=self._aura_export_recon_json_worker, args=(path,))
            t.daemon = True
            t.start()

        def _aura_export_recon_json_worker(self, path):
            try:
                data = {
                    "objects": self._aura_recon_result.get("objects", {}),
                    "home_urls": self._aura_recon_result.get("home_urls", {}),
                    "custom_controllers": self._aura_recon_result.get("custom_controllers", []),
                    "checks": self._aura_recon_result.get("checks", []),
                    "graphql_enabled": self._aura_recon_result.get("gql_enabled", False),
                }
                f = open(path, "wb")
                try:
                    f.write(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))
                finally:
                    f.close()
                self._log(u"Aura診断: 偵察結果をJSON出力しました: %s" % safe_text(path))
            except Exception as e:
                self._log(u"Aura診断: 偵察結果のエクスポートに失敗しました: %s" % safe_text(e))

        def _on_aura_export_recon_csv(self, event):
            if not self._aura_recon_has_results():
                self._log(u"Aura診断: 先に偵察を実行してください。")
                return
            chooser = JFileChooser()
            chooser.setDialogTitle(u"偵察結果CSVの保存先を選択")
            chooser.setSelectedFile(File("aura_recon_result.csv"))
            ret = chooser.showSaveDialog(self.main_panel)
            if ret != JFileChooser.APPROVE_OPTION:
                return
            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.lower().endswith(".csv"):
                path += ".csv"
            import threading
            t = threading.Thread(target=self._aura_export_recon_csv_worker, args=(path,))
            t.daemon = True
            t.start()

        def _aura_export_recon_csv_worker(self, path):
            """偵察結果（オブジェクト一覧／ホームURL／カスタムコントローラ／チェック結果という
            形の異なる4種のデータ）を、区分列を持つ単一のtall形式CSVにまとめて出力する。
            書き込みパターンは他のCSV出力（_export_vuln_csv_worker等）と同一。"""
            try:
                header = [u"区分", u"名前/項目", u"KeyPrefix", u"件数", u"UI検出", u"URL/備考", u"結果"]
                rows = []
                objects = self._aura_recon_result.get("objects", {})
                for name, row in objects.items():
                    ui_list = row.get("ui_list")
                    ui_text = u"あり" if ui_list else (u"なし" if ui_list is not None else u"-")
                    count = row.get("count")
                    rows.append([u"オブジェクト", name, safe_text(row.get("key_prefix", u"")),
                                 safe_text(count) if count is not None else u"-", ui_text,
                                 safe_text(row.get("note", u"")), u""])
                for name, url in self._aura_recon_result.get("home_urls", {}).items():
                    rows.append([u"ホームURL", name, u"", u"", u"", safe_text(url), u""])
                for controller, src_url in self._aura_recon_result.get("custom_controllers", []):
                    rows.append([u"カスタムコントローラ", safe_text(controller), u"", u"", u"", safe_text(src_url), u""])
                for label, result in self._aura_recon_result.get("checks", []):
                    rows.append([u"チェック結果", safe_text(label), u"", u"", u"", u"", safe_text(result)])

                f = open(path, "wb")
                try:
                    f.write(u"\ufeff".encode("utf-8"))
                    writer = csv.writer(f)
                    writer.writerow([safe_text(c).encode("utf-8") for c in header])
                    for row in rows:
                        writer.writerow([safe_text(c).encode("utf-8") for c in row])
                finally:
                    f.close()
                self._log(u"Aura診断: 偵察結果をCSV出力しました: %s (%d 行)" % (safe_text(path), len(rows)))
            except Exception as e:
                self._log(u"Aura診断: 偵察結果のCSVエクスポートに失敗しました: %s" % safe_text(e))

        # --- ③ データ抽出 ---

        def _on_aura_select_all_objects(self, event):
            if self.aura_extract_object_table_model.getRowCount() > 0:
                self.aura_extract_object_table.selectAll()

        def _on_aura_clear_object_selection(self, event):
            self.aura_extract_object_table.clearSelection()

        def _on_aura_extract_run(self, event):
            if not self._aura_session:
                self._log(u"Aura診断: 先に対象を設定してください。")
                return
            if not self.aura_arm_chk.isSelected():
                self._log(u"Aura診断: 「アクティブ送信を有効にする」にチェックを入れてから実行してください。")
                return
            view_rows = list(self.aura_extract_object_table.getSelectedRows())
            if not view_rows:
                self._log(u"Aura診断: 抽出対象のオブジェクトを選択してください（②偵察を先に実行してください）。")
                return
            # ソート後は表示上の行順とモデルの行順がずれるため、必ずconvertRowIndexToModelを
            # 経由してからモデルの値（オブジェクトAPI名列=0）を読む。
            target_objects = [
                self.aura_extract_object_table_model.getValueAt(
                    self.aura_extract_object_table.convertRowIndexToModel(r), 0)
                for r in view_rows
            ]
            try:
                row_cap = int((self.aura_row_cap_field.getText() or u"5000").strip())
            except Exception:
                row_cap = 5000
            try:
                delay_ms = int((self.aura_delay_field.getText() or u"200").strip())
            except Exception:
                delay_ms = 200

            session = self._aura_session
            est_requests = max(1, (len(target_objects) + 99) // 100) * max(1, (row_cap + 1999) // 2000)
            detail = JTextArea(
                u"対象ホスト: %s://%s:%s\n"
                u"対象オブジェクト: %d件\n%s\n\n"
                u"1オブジェクトあたりの取得上限: %d件\n"
                u"推定リクエスト数: 概算 %d件以上（オブジェクト・ページ数に応じて変動、間隔%dms）\n\n"
                u"本機能は対象ホストへ実際にHTTPリクエストを送信します。\n"
                u"認可された脆弱性診断対象であることを必ず確認してください。\n"
                u"未認可のホストに対して実行すると、不正アクセス行為に該当するおそれがあります。"
                % (session["protocol"], session["host"], session["port"], len(target_objects),
                   u"\n".join(u"  ・%s" % o for o in target_objects), row_cap, est_requests, delay_ms))
            detail.setEditable(False)
            detail.setLineWrap(True)
            detail_scroll = JScrollPane(detail)
            detail_scroll.setPreferredSize(Dimension(520, 260))

            options = [u"キャンセル", u"実行する"]
            choice = JOptionPane.showOptionDialog(
                self.main_panel, detail_scroll, u"データ抽出の実行確認",
                JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE, None,
                options, options[0])
            if choice != 1:
                self._log(u"Aura診断: データ抽出をキャンセルしました。")
                return

            import threading
            t = threading.Thread(target=self._aura_extract_worker, args=(target_objects, row_cap, delay_ms))
            t.daemon = True
            t.start()

        def _aura_getitems_row_id(self, row):
            try:
                rid = row.get("id") or row.get("Id")
                if isinstance(rid, dict):
                    rid = rid.get("value")
                if rid:
                    return safe_text(rid)
                return safe_text(json.dumps(row, sort_keys=True))
            except Exception:
                return safe_text(json.dumps(row, sort_keys=True) if row else u"")

        def _aura_extract_object_graphql(self, object_name, field_names, row_cap, delay_sec):
            """-> (rows, incomplete, note, session_expired)"""
            import time
            rows = []
            after_cursor = None
            note = u""
            while len(rows) < row_cap:
                page_size = min(2000, row_cap - len(rows))
                action = build_graphql_rows_action(u"rows", object_name, field_names,
                                                    page_size=page_size, after_cursor=after_cursor)
                _, resp_json, resp_text = self._aura_send_actions([action])
                if self._looks_like_auth_error(resp_text):
                    return rows, True, u"セッション切れ", True
                by_id = extract_action_responses_by_id(resp_json)
                new_rows, end_cursor, has_next, _total, errors = parse_graphql_rows_response(
                    by_id.get(u"rows"), object_name, field_names)
                if errors:
                    note = safe_text(flatten_for_csv(json.dumps(errors), 200))
                rows.extend(new_rows)
                if not new_rows or not has_next or not end_cursor:
                    break
                after_cursor = end_cursor
                time.sleep(delay_sec)
            incomplete = len(rows) >= row_cap
            if incomplete:
                note = (note + u" " if note else u"") + u"取得上限に到達"
            return rows, incomplete, note, False

        def _aura_extract_object_getitems(self, object_name, row_cap, delay_sec):
            """-> (rows, incomplete, note, session_expired)。GraphQL不可時のフォールバック。
            2,000件のgetItemsページ上限に達した場合は sortBy=Name/-Name で再取得し、
            IDで重複排除して取りこぼしを減らす（Mandiantブログ記事の手法。完全性は保証しない）。"""
            import time
            rows = []
            page_size = min(100, row_cap) if row_cap > 0 else 100
            current_page = 1
            note = u""
            while len(rows) < row_cap and len(rows) < 2000:
                action = build_getitems_full_action(u"rows", object_name, page_size, current_page)
                _, resp_json, resp_text = self._aura_send_actions([action])
                if self._looks_like_auth_error(resp_text):
                    return rows, True, u"セッション切れ", True
                by_id = extract_action_responses_by_id(resp_json)
                new_rows = parse_getitems_records(by_id.get(u"rows"))
                if not new_rows:
                    break
                rows.extend(new_rows)
                current_page += 1
                time.sleep(delay_sec)
            incomplete = False
            if len(rows) >= 2000 and len(rows) < row_cap:
                self._log(u"Aura診断: %s は getItems の2000件上限に到達。"
                          u"sortBy=Name/-Name で再取得を試みます（完全性は保証されません）。"
                          % safe_text(object_name))
                seen_ids = set(self._aura_getitems_row_id(r) for r in rows)
                for sort_by in (u"Name", u"-Name"):
                    page = 1
                    while len(rows) < row_cap:
                        action = build_getitems_full_action(u"rows2", object_name, 100, page, sort_by=sort_by)
                        _, resp_json, resp_text = self._aura_send_actions([action])
                        if self._looks_like_auth_error(resp_text):
                            return rows, True, u"セッション切れ", True
                        by_id = extract_action_responses_by_id(resp_json)
                        extra_rows = parse_getitems_records(by_id.get(u"rows2"))
                        if not extra_rows:
                            break
                        added_any = False
                        for r in extra_rows:
                            rid = self._aura_getitems_row_id(r)
                            if rid not in seen_ids:
                                seen_ids.add(rid)
                                rows.append(r)
                                added_any = True
                        if not added_any:
                            break
                        page += 1
                        time.sleep(delay_sec)
                incomplete = True
                note = u"2000件超の可能性あり（sortBy再取得を実施済み・完全性は未保証）"
            if len(rows) >= row_cap:
                incomplete = True
                note = (note + u" " if note else u"") + u"取得上限に到達"
            return rows, incomplete, note, False

        def _aura_finish_extraction(self):
            total_rows = sum(len(v) for v in self._aura_extract_results.values())
            self._log(u"Aura診断: データ抽出が完了しました（%d オブジェクト、合計%d件、"
                      u"部分結果を含む）。エクスポートボタンから保存できます。"
                      % (len(self._aura_extract_results), total_rows))

        def _aura_extract_worker(self, target_objects, row_cap, delay_ms):
            self._log(u"Aura診断: データ抽出を開始します（対象 %d件）。" % len(target_objects))
            self._aura_extract_results = {}
            gql_enabled = bool(self._aura_recon_result.get("gql_enabled"))
            progress_rows = {}

            def update_progress(name, status, count, method, note=u""):
                progress_rows[name] = [name, status, count, method, note]
                def do_update():
                    self.aura_extract_table_model.setRowCount(0)
                    for n in target_objects:
                        if n in progress_rows:
                            self.aura_extract_table_model.addRow(progress_rows[n])
                        else:
                            self.aura_extract_table_model.addRow([n, u"待機中", None, u"-", u""])
                SwingUtilities.invokeLater(do_update)

            for name in target_objects:
                update_progress(name, u"待機中", None, u"GraphQL" if gql_enabled else u"getItems")

            fields_by_object = {}
            if gql_enabled:
                for chunk in chunk_actions(target_objects, 100):
                    _, resp_json, resp_text = self._aura_send_actions(
                        [build_graphql_fields_action(u"fields", chunk)])
                    if self._looks_like_auth_error(resp_text):
                        self._log(u"Aura診断: セッションが無効なようです。抽出を中断します。"
                                  u"再キャプチャして対象を再設定してください。")
                        self._aura_finish_extraction()
                        return
                    by_id = extract_action_responses_by_id(resp_json)
                    fields_by_object.update(parse_graphql_fields_response(by_id.get(u"fields")))

            delay_sec = max(0, delay_ms) / 1000.0
            import time as _time_mod

            for name in target_objects:
                update_progress(name, u"実行中", None, u"GraphQL" if gql_enabled else u"getItems")
                try:
                    if gql_enabled and fields_by_object.get(name):
                        rows, incomplete, note, expired = self._aura_extract_object_graphql(
                            name, fields_by_object[name], row_cap, delay_sec)
                        method = u"GraphQL"
                    else:
                        rows, incomplete, note, expired = self._aura_extract_object_getitems(
                            name, row_cap, delay_sec)
                        method = u"getItems"
                        if not expired:
                            field_caveat = u"フィールドは一覧レイアウト依存（GraphQL未使用のため一部欠落の可能性）"
                            note = (note + u" " if note else u"") + field_caveat
                    self._aura_extract_results[name] = rows
                    if expired:
                        update_progress(name, u"中断（セッション切れ）", len(rows), method, note)
                        self._log(u"Aura診断: セッションが無効なようです。抽出を中断します。"
                                  u"再キャプチャして対象を再設定してください。")
                        break
                    if incomplete:
                        note = (note + u" " if note else u"") + u"不完全な可能性あり"
                    update_progress(name, u"完了", len(rows), method, note)
                    self._log(u"Aura診断: %s: %d 件取得（%s）" % (safe_text(name), len(rows), method))
                except Exception as e:
                    update_progress(name, u"エラー", 0, u"-", safe_text(e))
                    self._log(u"Aura診断: %s の抽出でエラー: %s" % (safe_text(name), safe_text(e)))
                _time_mod.sleep(delay_sec)

            self._aura_finish_extraction()

        def _on_aura_export_csv(self, event):
            if not getattr(self, "_aura_extract_results", None):
                self._log(u"Aura診断: 先にデータ抽出を実行してください。")
                return
            chooser = JFileChooser()
            chooser.setDialogTitle(u"抽出結果CSVの保存先を選択")
            chooser.setSelectedFile(File("aura_extracted_records.csv"))
            ret = chooser.showSaveDialog(self.main_panel)
            if ret != JFileChooser.APPROVE_OPTION:
                return
            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.lower().endswith(".csv"):
                path += ".csv"
            import threading
            t = threading.Thread(target=self._aura_export_csv_worker, args=(path,))
            t.daemon = True
            t.start()

        def _aura_export_csv_worker(self, path):
            """抽出結果をtall/long形式のCSVで出力する
            （ObjectApiName, RecordId, FieldName, FieldValueの4列。1行=1フィールド値。
            オブジェクトごとにスキーマが異なっても1ファイルで自然に扱えるため、この形式にしている）。
            書き込みパターンはワード照合一覧CSV出力（_export_vuln_csv_worker）と同一。"""
            try:
                f = open(path, "wb")
                try:
                    f.write(u"\ufeff".encode("utf-8"))
                    writer = csv.writer(f)
                    writer.writerow([safe_text(c).encode("utf-8") for c in
                                      [u"ObjectApiName", u"RecordId", u"FieldName", u"FieldValue"]])
                    row_count = 0
                    for object_name, rows in self._aura_extract_results.items():
                        for row in rows:
                            record_id = safe_text(row.get("Id") or row.get("id") or u"")
                            for field_name, value in row.items():
                                writer.writerow([safe_text(c).encode("utf-8") for c in [
                                    object_name, record_id, field_name,
                                    flatten_for_csv(safe_text(value)),
                                ]])
                                row_count += 1
                finally:
                    f.close()
                self._log(u"Aura診断: 抽出結果をCSV出力しました: %s (%d 行)" % (safe_text(path), row_count))
            except Exception as e:
                self._log(u"Aura診断: CSV出力エラー: %s" % safe_text(e))

        def _on_aura_export_json(self, event):
            if not getattr(self, "_aura_extract_results", None):
                self._log(u"Aura診断: 先にデータ抽出を実行してください。")
                return
            chooser = JFileChooser()
            chooser.setDialogTitle(u"抽出結果JSONの保存先を選択")
            chooser.setSelectedFile(File("aura_extracted_records.json"))
            ret = chooser.showSaveDialog(self.main_panel)
            if ret != JFileChooser.APPROVE_OPTION:
                return
            path = chooser.getSelectedFile().getAbsolutePath()
            if not path.lower().endswith(".json"):
                path += ".json"
            import threading
            t = threading.Thread(target=self._aura_export_json_worker, args=(path,))
            t.daemon = True
            t.start()

        def _aura_export_json_worker(self, path):
            try:
                f = open(path, "wb")
                try:
                    f.write(json.dumps(self._aura_extract_results, ensure_ascii=False, indent=2).encode("utf-8"))
                finally:
                    f.close()
                total = sum(len(v) for v in self._aura_extract_results.values())
                self._log(u"Aura診断: 抽出結果をJSON出力しました: %s (%d件)" % (safe_text(path), total))
            except Exception as e:
                self._log(u"Aura診断: JSON出力エラー: %s" % safe_text(e))

        # ------------------------------------------------------------------------
        # IMessageEditorTabFactory
        # ------------------------------------------------------------------------
        def createNewInstance(self, controller, editable):
            return SFMessageEditorTab(self, controller)

        # ------------------------------------------------------------------------
        # IContextMenuFactory
        # ------------------------------------------------------------------------
        def createMenuItems(self, invocation):
            items = []
            selected = invocation.getSelectedMessages()
            if not selected:
                return items

            def do_number(event, sel=selected):
                self._number_selected(sel)

            def do_color(event, sel=selected):
                self._color_selected_as_agg(sel)

            def do_set_from(event, sel=selected):
                self._set_range_from_selected(sel, "from")

            def do_set_to(event, sel=selected):
                self._set_range_from_selected(sel, "to")

            def do_set_aura_target(event, sel=selected):
                self._set_aura_target_from_selected(sel)

            mi5 = JMenuItem(u"SF Helper: このパケットをAura診断対象に設定", actionPerformed=do_set_aura_target)
            items.append(mi5)
            mi1 = JMenuItem(u"SF Helper: 選択パケットに採番", actionPerformed=do_number)
            items.append(mi1)
            mi2 = JMenuItem(u"SF Helper: 選択パケットに予約色を適用", actionPerformed=do_color)
            items.append(mi2)
            mi3 = JMenuItem(u"SF Helper: [解析]表示範囲のToにこの採番番号をセット", actionPerformed=do_set_to)
            items.append(mi3)
            mi4 = JMenuItem(u"SF Helper: [解析]表示範囲のFromにこの採番番号をセット", actionPerformed=do_set_from)
            items.append(mi4)
            return items

        def _set_range_from_selected(self, selected_items, which):
            """右クリック選択パケットのComment先頭の採番番号を読み取り、[解析]タブの
            「表示対象の採番範囲」（From/To）にセットする。which は "from" または "to"。
            複数選択されている場合は先頭の1件を使う。セット後、解析済みであれば
            即座に集計・ワード照合一覧を再フィルタして結果を確認できるようにする。"""
            if not selected_items:
                return
            item = selected_items[0]
            if len(selected_items) > 1:
                self._log(u"複数選択されていますが、先頭の1件の採番番号を使用します。")
            comment = item.getComment() or ""
            n = self._leading_number_int(comment)
            if n is None:
                self._log(u"選択パケットのCommentに採番番号が見つかりません"
                          u"（先に[採番]タブで採番してください）。Comment=%s" % safe_text(comment))
                return
            label = u"From" if which == "from" else u"To"
            field = self.summary_from_field if which == "from" else self.summary_to_field
            field.setText(str(n))
            self._log(u"[解析]表示範囲の%sを %d にセットしました。" % (label, n))
            if self._packets_cache_exists():
                self._apply_range_and_populate(self._packets_cache)

        def _color_selected_as_agg(self, selected_items):
            """右クリック選択パケットに、無条件で予約色を適用する（集約判定を待たない簡易操作）。"""
            color = self.reserved_color
            count = 0
            for item in selected_items:
                try:
                    item.setHighlight(color)
                    count += 1
                except Exception as e:
                    self._log(u"選択色適用エラー: %s" % str(e))
            self._log(u"選択パケットに予約色(%s)を適用しました: %d 件" % (color, count))


    # ----------------------------------------------------------------------------
    # 選択中(カレント)パケット専用タブ
    # ----------------------------------------------------------------------------

    class SFMessageEditorTab(IMessageEditorTab):

        def __init__(self, extender, controller):
            self._extender = extender
            self._controller = controller
            self._current_content = None
            self._panel = JPanel(BorderLayout())
            self._text = JTextArea()
            self._text.setEditable(False)
            self._text.setFont(Font("Monospaced", Font.PLAIN, 12))
            self._panel.add(JScrollPane(self._text), BorderLayout.CENTER)

        def getTabCaption(self):
            return "SF Vuln/Agg"

        def getUiComponent(self):
            return self._panel

        def isEnabled(self, content, isRequest):
            # リクエスト用ルール×リクエスト内容、レスポンス用ルール×レスポンス内容を
            # それぞれ判定し、どちらかがヒットすればタブを表示する（どちらのペインを
            # 見ている場合(isRequest)でも同じ判定になるよう、controller経由で両方取得する）。
            if content is None:
                return False
            try:
                req_content = self._controller.getRequest() if self._controller else \
                    (content if isRequest else None)
                resp_content = self._controller.getResponse() if self._controller else \
                    (content if not isRequest else None)
            except Exception:
                req_content = content if isRequest else None
                resp_content = content if not isRequest else None
            request_words = []
            for r in self._extender.rules_request:
                request_words.extend(r["list1"])
                request_words.extend(r["list2"])
            response_words = []
            for r in self._extender.rules_response:
                response_words.extend(r["list1"])
                response_words.extend(r["list2"])
            req_hit = req_content is not None and \
                quick_relevant(self._extender._helpers, req_content, request_words)
            resp_hit = resp_content is not None and \
                quick_relevant(self._extender._helpers, resp_content, response_words)
            return req_hit or resp_hit

        def setMessage(self, content, isRequest):
            self._current_content = content
            if content is None:
                self._text.setText(u"")
                return
            try:
                req = self._controller.getRequest()
                resp = self._controller.getResponse()
                svc = self._controller.getHttpService()
                helpers = self._extender._helpers
                pkt = analyze_http_item(helpers, svc, req, resp)
                hits_request = match_rules(
                    self._extender.rules_request, pkt.corpus, self._extender.and_or_mode_request)
                hits_response = match_rules(
                    self._extender.rules_response, pkt.resp_corpus, self._extender.and_or_mode_response,
                    location_order=RESPONSE_LOCATION_ORDER)
                hits = merge_vuln_hits(hits_request, hits_response)

                lines = []
                lines.append(u"[分類] %s" % CLS_LABELS.get(pkt.cls_code, pkt.cls_code))
                lines.append(u"[Method/Path] %s %s" % (pkt.method, pkt.path))
                if pkt.descriptors:
                    lines.append(u"[Aura Descriptors] %s" % ", ".join(sorted(pkt.descriptors)))
                    if any(looks_like_lwc_apex_descriptor(d) for d in pkt.descriptors):
                        lines.append(u"  ※ ApexActionController経由のdescriptorが含まれています。"
                                      u"LWC(Lightning Web Components)からのimperative/wire Apex"
                                      u"呼び出しの可能性があります（断定はできません）。")
                if pkt.apex:
                    lines.append(u"[Apex] %s" % ", ".join(sorted(pkt.apex)))
                if pkt.objects:
                    lines.append(u"[Aura Objects] %s" % ", ".join(sorted(pkt.objects)))
                lines.append(u"[AggKey] %s" % pkt.agg_key)

                cached = self._extender.index_by_identity.get(pkt.identity)
                if cached is not None:
                    lines.append(u"[AggRole] %s (代表No.%s / グループ size=%s)"
                                  % (cached.agg_role, cached.agg_rep_no, cached.agg_group_size))
                else:
                    lines.append(u"[AggRole] 未解析（[解析]タブで[解析更新]を実行してください）")

                lines.append(u"")
                if hits:
                    lines.append(u"[ワード照合ヒット] (結合条件: REQ=%s / RESP=%s)"
                                  % (self._extender.and_or_mode_request, self._extender.and_or_mode_response))
                    for vuln_no, hs in hits:
                        loc_desc = ", ".join(
                            "%s(%s)" % (w, LOCATION_LABELS.get(loc, loc)) for (w, _l, loc) in hs)
                        lines.append(u"  Vuln-No %s : %s" % (vuln_no, loc_desc))
                else:
                    lines.append(u"[ワード照合ヒット] なし")

                self._text.setText(u"\n".join(lines))
                self._text.setCaretPosition(0)
            except Exception as e:
                self._text.setText(u"解析エラー: %s" % str(e))

        def getMessage(self):
            return self._current_content

        def isModified(self):
            return False

        def getSelectedData(self):
            return self._text.getSelectedText()
