import Component from "@glimmer/component";
import { tracked } from "@glimmer/tracking";
import { action } from "@ember/object";
import { service } from "@ember/service";
import { on } from "@ember/modifier";
import { registerDestructor } from "@ember/destroyable";
import DModal from "discourse/components/d-modal";
import DButton from "discourse/components/d-button";
import {
  deriveSeed,
  ed25519KeysFromSeed,
  sign,
  canonicalJsonStruct,
  toBase64Std,
  toHex,
} from "../lib/crypto";
import {
  BALANCE_CHANGED_EVENT,
  WALLET_BASE,
  formatPoints,
  jsonFetch,
  walletLoginUrl,
} from "../lib/wallet-api";

const AMOUNT_PRESETS = ["1", "10", "50", "100"];

export default class TipModal extends Component {
  @service currentUser;
  @service toasts;

  @tracked amount = "1";
  @tracked password = "";
  @tracked status = "idle"; // idle | working | success | error
  @tracked accountStatus = "loading"; // loading | ok | auth | error
  @tracked accountError = "";
  @tracked errorMsg = "";
  @tracked working = ""; // fetching | deriving | registering | signing | submitting
  @tracked me = null;

  closeTimer = null;
  _destroyed = false;
  _accountRequestId = 0;

  constructor() {
    super(...arguments);
    registerDestructor(this, () => {
      this._destroyed = true;
      if (this.closeTimer) {
        clearTimeout(this.closeTimer);
      }
    });
    this.loadAccount();
  }

  get targetId() {
    return Number(this.args.model.targetId);
  }

  get targetUsername() {
    return this.args.model.targetUsername ?? "";
  }

  get targetPostId() {
    return this.args.model.targetPostId;
  }

  get title() {
    return `打赏 @${this.targetUsername}`;
  }

  get amountPresets() {
    return AMOUNT_PRESETS;
  }

  get amountString() {
    return String(this.amount);
  }

  get amountValue() {
    const n = Number(this.amount);
    return Number.isInteger(n) ? n : NaN;
  }

  get hasValidAmount() {
    return Number.isInteger(this.amountValue) && this.amountValue >= 1;
  }

  get isWorking() {
    return this.status === "working";
  }

  get isSuccess() {
    return this.status === "success";
  }

  get isAccountLoading() {
    return this.accountStatus === "loading";
  }

  get needsAuth() {
    return this.accountStatus === "auth";
  }

  get isAccountError() {
    return this.accountStatus === "error";
  }

  get accountReady() {
    return this.accountStatus === "ok";
  }

  get formattedBalance() {
    return formatPoints(this.me?.balance ?? 0);
  }

  get accountStateLabel() {
    if (!this.me) {
      return "未连接";
    }
    return this.me.activated ? "已激活" : "待激活";
  }

  get hasInsufficientFunds() {
    if (!this.accountReady || !this.hasValidAmount) {
      return false;
    }
    return this.amountValue > Number(this.me?.balance ?? 0);
  }

  get amountHint() {
    if (!this.hasValidAmount) {
      return "请输入大于 0 的整数。";
    }
    if (this.hasInsufficientFunds) {
      return `余额不足, 当前 ${this.formattedBalance} pts。`;
    }
    return "";
  }

  get progressText() {
    switch (this.working) {
      case "fetching":
        return "正在校验账户...";
      case "deriving":
        return "正在本地派生签名密钥...";
      case "registering":
        return "正在激活钱包...";
      case "signing":
        return "正在签名交易...";
      case "submitting":
        return "正在提交交易...";
      default:
        return "正在处理...";
    }
  }

  get submitLabel() {
    if (this.isWorking) {
      return "处理中...";
    }
    if (this.isSuccess) {
      return "已完成";
    }
    return "确认打赏";
  }

  get canSubmit() {
    return this.accountReady
      && this.status !== "working"
      && this.status !== "success"
      && this.hasValidAmount
      && !this.hasInsufficientFunds
      && this.password.length > 0;
  }

  clearSubmissionError() {
    if (this.status === "error") {
      this.status = "idle";
      this.errorMsg = "";
    }
  }

  @action
  setAmount(e) {
    this.amount = e.target.value.trim();
    this.clearSubmissionError();
  }

  @action
  chooseAmount(e) {
    this.amount = e.currentTarget.dataset.amount;
    this.clearSubmissionError();
  }

  @action
  setPassword(e) {
    this.password = e.target.value;
    this.clearSubmissionError();
  }

  @action
  submitOnEnter(e) {
    if (e.key === "Enter") {
      e.preventDefault();
      this.submit();
    }
  }

  @action
  loginWallet() {
    window.location.href = walletLoginUrl();
  }

  @action
  retryAccount() {
    this.loadAccount();
  }

  async loadAccount({ redirectOnAuth = false } = {}) {
    const requestId = ++this._accountRequestId;
    this.accountStatus = "loading";
    this.accountError = "";

    try {
      const resp = await jsonFetch(`${WALLET_BASE}/me`);
      if (this._destroyed || requestId !== this._accountRequestId) {
        return null;
      }

      if (resp.status === 401) {
        this.me = null;
        this.accountStatus = "auth";
        if (redirectOnAuth) {
          window.location.href = walletLoginUrl();
        }
        return null;
      }

      if (!resp.ok) {
        throw new Error(resp.data?.error ?? `HTTP ${resp.status}`);
      }

      this.me = resp.data;
      this.accountStatus = "ok";
      return this.me;
    } catch (e) {
      if (!this._destroyed && requestId === this._accountRequestId) {
        this.me = null;
        this.accountStatus = "error";
        this.accountError = e.message ?? String(e);
      }
      return null;
    }
  }

  @action
  async submit() {
    if (!this.canSubmit) {
      return;
    }

    this.status = "working";
    this.errorMsg = "";
    this.working = "fetching";

    let seed = null;
    let amount = 0;

    try {
      if (!this.currentUser?.id) {
        throw new Error("请先登录论坛账户。");
      }
      if (!Number.isInteger(this.targetId) || this.targetId <= 0) {
        throw new Error("目标用户无效, 无法打赏。");
      }

      const me = await this.loadAccount({ redirectOnAuth: true });
      if (!me) {
        this.status = "idle";
        return;
      }

      amount = this.amountValue;
      if (!Number.isInteger(amount) || amount < 1) {
        throw new Error("金额必须是大于 0 的整数。");
      }
      if (amount > Number(me.balance ?? 0)) {
        throw new Error(`余额不足, 当前 ${formatPoints(me.balance ?? 0)} pts。`);
      }

      this.working = "deriving";
      seed = await deriveSeed(this.password, this.currentUser.id);
      const { privKey, pubKey } = await ed25519KeysFromSeed(seed);
      const myPubHex = toHex(pubKey);

      if (!me.registered) {
        this.working = "registering";
        const reg = await jsonFetch(`${WALLET_BASE}/me/register`, {
          method: "POST",
          body: JSON.stringify({ pubkey_hex: myPubHex }),
        });
        if (!reg.ok) {
          throw new Error(reg.data?.error ?? `register failed: ${reg.status}`);
        }
        Object.assign(me, reg.data ?? {}, {
          registered: true,
          activated: true,
          pubkey_hex: myPubHex,
        });
        this.me = me;
      }

      if ((me.pubkey_hex ?? "").toLowerCase() !== myPubHex) {
        throw new Error(
          "账户登记的公钥与本次密码派生不一致。你可能改过论坛密码, 需要先完成 rotate_key 流程。",
        );
      }

      const nonce = (me.nonce ?? 0) + 1;
      const meta = {
        tip_target_post_id: this.targetPostId,
        tip_target_user_id: this.targetId,
        tip_target_username: this.targetUsername,
      };

      this.working = "signing";
      const payload = canonicalJsonStruct([
        ["from", pubKey],
        ["to_discourse_id", this.targetId],
        ["amount", amount],
        ["nonce", nonce],
        ["meta", meta],
      ]);
      const sig = await sign(privKey, payload);

      this.working = "submitting";
      const submit = await jsonFetch(`${WALLET_BASE}/tx`, {
        method: "POST",
        body: JSON.stringify({
          tx_type: "transfer",
          payload_b64: toBase64Std(payload),
          sig_b64: toBase64Std(sig),
          signer_hex: myPubHex,
        }),
      });

      if (!submit.ok) {
        throw new Error(submit.data?.error ?? `tx failed: ${submit.status}`);
      }

      this.status = "success";
      this.toasts?.success?.({ data: { message: `已打赏 ${amount} pts 给 ${this.targetUsername}` } });
      document.dispatchEvent(new CustomEvent(BALANCE_CHANGED_EVENT, {
        detail: { ids: [Number(this.currentUser.id), this.targetId] },
      }));
      this.closeTimer = setTimeout(() => this.args.closeModal?.(), 800);
    } catch (e) {
      this.status = "error";
      this.errorMsg = e.message ?? String(e);
      // eslint-disable-next-line no-console
      console.warn("[forum-points] tip failed:", e);
    } finally {
      if (seed) {
        seed.fill(0);
      }
      this.password = "";
      this.working = "";
    }
  }

  <template>
    <DModal
      @translatedTitle={{this.title}}
      @closeModal={{@closeModal}}
      class="forum-points-tip-modal"
    >
      <:body>
        <div class="fp-modal__body">
          {{#if this.isAccountLoading}}
            <div class="fp-modal__notice">正在读取钱包账户...</div>
          {{else if this.needsAuth}}
            <div class="fp-modal__notice">
              当前浏览器还没有钱包会话, 需要先连接 Discourse 登录态。
            </div>
          {{else if this.isAccountError}}
            <div class="fp-modal__error">账户读取失败: {{this.accountError}}</div>
          {{else}}
            <div class="fp-modal__summary">
              <div>
                <span class="fp-modal__summary-label">可用余额</span>
                <strong>{{this.formattedBalance}}</strong>
                <span>pts</span>
              </div>
              <span class="fp-modal__account-state">{{this.accountStateLabel}}</span>
            </div>
          {{/if}}

          {{#if (eq this.status "error")}}
            <div class="fp-modal__error">{{this.errorMsg}}</div>
          {{/if}}

          <label class="fp-modal__field">
            <span>金额 (pts)</span>
            <input
              type="number"
              min="1"
              step="1"
              inputmode="numeric"
              value={{this.amount}}
              {{on "input" this.setAmount}}
              disabled={{or this.isWorking this.needsAuth this.isAccountLoading this.isAccountError}}
            />
          </label>

          <div class="fp-modal__quick-amounts">
            {{#each this.amountPresets as |preset|}}
              <button
                type="button"
                class={{if (eq this.amountString preset) "fp-quick-amount fp-quick-amount--active" "fp-quick-amount"}}
                data-amount={{preset}}
                disabled={{or this.isWorking this.needsAuth this.isAccountLoading this.isAccountError}}
                {{on "click" this.chooseAmount}}
              >
                {{preset}}
              </button>
            {{/each}}
          </div>

          {{#if this.amountHint}}
            <div class="fp-modal__hint">{{this.amountHint}}</div>
          {{/if}}

          <label class="fp-modal__field">
            <span>论坛登录密码</span>
            <input
              type="password"
              autocomplete="current-password"
              value={{this.password}}
              {{on "input" this.setPassword}}
              {{on "keydown" this.submitOnEnter}}
              disabled={{or this.isWorking this.needsAuth this.isAccountLoading this.isAccountError}}
            />
          </label>
          <div class="fp-modal__hint">密码只在本地派生签名密钥, 不会上传。</div>

          {{#if this.isWorking}}
            <div class="fp-modal__progress">{{this.progressText}}</div>
          {{else if this.isSuccess}}
            <div class="fp-modal__success">已打赏。</div>
          {{/if}}
        </div>
      </:body>
      <:footer>
        <DButton
          @translatedLabel="取消"
          @action={{@closeModal}}
        />

        {{#if this.needsAuth}}
          <DButton
            @translatedLabel="连接钱包会话"
            @action={{this.loginWallet}}
            class="btn-primary"
          />
        {{else if this.isAccountError}}
          <DButton
            @translatedLabel="重试"
            @action={{this.retryAccount}}
            class="btn-primary"
          />
        {{else}}
          <DButton
            @translatedLabel={{this.submitLabel}}
            @action={{this.submit}}
            @disabled={{not this.canSubmit}}
            class="btn-primary"
          />
        {{/if}}
      </:footer>
    </DModal>
  </template>
}

function eq(a, b) {
  return a === b;
}

function not(a) {
  return !a;
}

function or(...args) {
  return args.some(Boolean);
}
