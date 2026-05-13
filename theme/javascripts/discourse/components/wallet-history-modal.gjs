// Public account history. Anyone may inspect a user's PTS ledger entries.

import Component from "@glimmer/component";
import { tracked } from "@glimmer/tracking";
import { action } from "@ember/object";
import { registerDestructor } from "@ember/destroyable";
import DModal from "discourse/components/d-modal";
import DButton from "discourse/components/d-button";
import {
  WALLET_BASE,
  explorerTxUrl,
  formatPoints,
  jsonFetch,
} from "../lib/wallet-api";

function shortName(name) {
  if (!name) {
    return "-";
  }
  if (name === "TREASURY") {
    return "Treasury";
  }
  return `@${name}`;
}

function describeEntry(e, viewerId) {
  if (e.tx_type === "rotate_key") {
    return { label: "密钥轮换", color: "neutral", sign: "" };
  }
  if (e.tx_type !== "transfer") {
    return { label: e.tx_type, color: "neutral", sign: "" };
  }

  const isSender = e.from_discourse_id === viewerId;
  const src = e.meta?.reward_source ?? "";

  if (isSender) {
    if (e.meta?.tip_target_post_id) {
      return { label: `打赏帖子 #${e.meta.tip_target_post_id}`, color: "sent", sign: "-" };
    }
    return { label: "转出", color: "sent", sign: "-" };
  }

  if (src.endsWith("signup_bonus")) {
    return { label: "注册激活奖励", color: "received", sign: "+" };
  }
  if (src.endsWith("first_post_ever")) {
    return { label: "首帖奖励", color: "received", sign: "+" };
  }
  if (src === "quality_post") {
    return { label: "优质帖奖励", color: "received", sign: "+" };
  }
  if (e.meta?.tip_target_post_id) {
    return { label: `收到打赏, post #${e.meta.tip_target_post_id}`, color: "received", sign: "+" };
  }
  return { label: "转入", color: "received", sign: "+" };
}

class Row {
  constructor(e, viewerId) {
    const d = describeEntry(e, viewerId);

    this.entry = e;
    this.id = e.leaf_index;
    this.ts = (e.created_at || "").replace("T", " ").replace("Z", " UTC");
    this.amount = formatPoints(e.amount);
    this.counterparty = shortName(e.counterparty_name);
    this.label = d.label;
    this.sign = d.sign;
    this.color = d.color;
    this.href = explorerTxUrl(e.tx_hash_hex, e.leaf_index);
    this.rowClass = `fp-history__row fp-history__row--${d.color}`;
    this.amtClass = `fp-history__col-amt fp-history__col-amt--${d.color}`;
  }
}

export default class WalletHistoryModal extends Component {
  @tracked rows = null;
  @tracked status = "loading"; // loading | ok | error
  @tracked errorMsg = "";

  _destroyed = false;
  _loadId = 0;

  constructor() {
    super(...arguments);
    registerDestructor(this, () => {
      this._destroyed = true;
    });
    this.load();
  }

  get viewerId() {
    return Number(this.args.model.discourseId);
  }

  get viewerUsername() {
    return this.args.model.username ?? "";
  }

  get rowCount() {
    return this.rows ? this.rows.length : 0;
  }

  get isLoading() {
    return this.status === "loading";
  }

  get isError() {
    return this.status === "error";
  }

  get isEmpty() {
    return this.status === "ok" && this.rowCount === 0;
  }

  get isOK() {
    return this.status === "ok" && this.rowCount > 0;
  }

  get title() {
    return `钱包流水 @${this.viewerUsername}`;
  }

  @action
  refresh() {
    this.load();
  }

  async load() {
    const loadId = ++this._loadId;
    this.status = "loading";
    this.errorMsg = "";

    try {
      if (!Number.isInteger(this.viewerId) || this.viewerId < 0) {
        throw new Error("bad user id");
      }

      const { ok, status, data } = await jsonFetch(
        `${WALLET_BASE}/history/${this.viewerId}?limit=100`,
      );
      if (!ok) {
        throw new Error(data?.error ?? `HTTP ${status}`);
      }

      const entries = data.entries ?? [];
      if (this._destroyed || loadId !== this._loadId) {
        return;
      }

      this.rows = entries.map((e) => new Row(e, this.viewerId));
      this.status = "ok";
    } catch (e) {
      if (this._destroyed || loadId !== this._loadId) {
        return;
      }
      this.status = "error";
      this.errorMsg = e.message ?? String(e);
    }
  }

  <template>
    <DModal
      @translatedTitle={{this.title}}
      @closeModal={{@closeModal}}
      class="forum-points-history-modal"
    >
      <:body>
        <div class="fp-history__body">
          {{#if this.isLoading}}
            <div class="fp-history__loading">加载中...</div>
          {{else if this.isError}}
            <div class="fp-history__error">加载失败: {{this.errorMsg}}</div>
          {{else if this.isEmpty}}
            <div class="fp-history__empty">这个账户还没有任何流水。</div>
          {{else if this.isOK}}
            <div class="fp-history__table-wrap">
              <table class="fp-history__table">
                <thead>
                  <tr>
                    <th>时间 (UTC)</th>
                    <th>事件</th>
                    <th>对方</th>
                    <th class="fp-history__col-amt">金额 (pts)</th>
                    <th>审计</th>
                  </tr>
                </thead>
                <tbody>
                  {{#each this.rows as |r|}}
                    <tr class={{r.rowClass}}>
                      <td>{{r.ts}}</td>
                      <td>{{r.label}}</td>
                      <td>{{r.counterparty}}</td>
                      <td class={{r.amtClass}}>{{r.sign}}{{r.amount}}</td>
                      <td>
                        <a
                          href={{r.href}}
                          target="_blank"
                          rel="noopener noreferrer"
                          class="fp-history__leaf-link"
                        >
                          #{{r.id}}
                        </a>
                      </td>
                    </tr>
                  {{/each}}
                </tbody>
              </table>
            </div>
            <div class="fp-history__footnote">
              最近 {{this.rowCount}} 笔。交易已签名并写入公开 Merkle 日志。
            </div>
          {{/if}}
        </div>
      </:body>
      <:footer>
        <DButton
          @translatedLabel="关闭"
          @action={{@closeModal}}
        />
        <DButton
          @translatedLabel={{if this.isLoading "刷新中..." "刷新"}}
          @action={{this.refresh}}
          @disabled={{this.isLoading}}
          class="btn-primary"
        />
      </:footer>
    </DModal>
  </template>
}
