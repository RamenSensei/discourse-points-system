import Component from "@glimmer/component";
import { tracked } from "@glimmer/tracking";
import { action } from "@ember/object";
import { service } from "@ember/service";
import { on } from "@ember/modifier";
import { registerDestructor } from "@ember/destroyable";
import WalletHistoryModal from "../../components/wallet-history-modal";
import {
  BALANCE_CHANGED_EVENT,
  fetchAccount,
  formatPoints,
  invalidateBalances,
} from "../../lib/wallet-api";

export default class ForumPointsBalance extends Component {
  @service modal;

  @tracked account = null;
  @tracked status = "loading"; // loading | ok | error
  @tracked errorMsg = "";

  _destroyed = false;
  _loadId = 0;

  constructor() {
    super(...arguments);

    this.onBalanceChanged = (event) => {
      const ids = event.detail?.ids ?? [];
      const normalized = ids.map((id) => Number(id)).filter(Number.isFinite);
      if (!event.detail?.fpBalancesInvalidated) {
        invalidateBalances(normalized);
        if (event.detail) {
          event.detail.fpBalancesInvalidated = true;
        }
      }
      if (normalized.length === 0 || normalized.includes(Number(this.userId))) {
        this.load({ force: true });
      }
    };

    document.addEventListener(BALANCE_CHANGED_EVENT, this.onBalanceChanged);
    registerDestructor(this, () => {
      this._destroyed = true;
      document.removeEventListener(BALANCE_CHANGED_EVENT, this.onBalanceChanged);
    });

    this.load();
  }

  get user() {
    return this.args.outletArgs?.user ?? this.args.outletArgs?.model ?? null;
  }

  get userId() {
    return this.user?.id;
  }

  get username() {
    return this.user?.username ?? this.account?.username ?? "";
  }

  get isLoading() {
    return this.status === "loading";
  }

  get isError() {
    return this.status === "error";
  }

  get isOk() {
    return this.status === "ok";
  }

  get formattedBalance() {
    return formatPoints(this.account?.balance ?? 0);
  }

  get activationLabel() {
    if (!this.account || this.account.activated) {
      return "";
    }
    return "待激活";
  }

  get title() {
    if (this.isError) {
      return `重新读取 @${this.username} 的钱包余额`;
    }
    return `查看 @${this.username} 的钱包流水`;
  }

  get ariaLabel() {
    if (this.isLoading) {
      return `正在读取 @${this.username} 的 PTS 余额`;
    }
    if (this.isError) {
      return `重新读取 @${this.username} 的 PTS 余额`;
    }
    return `@${this.username} 的 PTS 余额 ${this.formattedBalance} pts`;
  }

  async load({ force = false } = {}) {
    const id = Number(this.userId);
    const loadId = ++this._loadId;

    if (!Number.isInteger(id) || id <= 0) {
      this.status = "error";
      this.errorMsg = "bad user id";
      return;
    }

    this.status = "loading";
    this.errorMsg = "";

    try {
      const account = await fetchAccount(id, { force });
      if (this._destroyed || loadId !== this._loadId) {
        return;
      }
      this.account = account;
      this.status = "ok";
    } catch (e) {
      if (this._destroyed || loadId !== this._loadId) {
        return;
      }
      this.errorMsg = e.message ?? String(e);
      this.status = "error";
      // eslint-disable-next-line no-console
      console.warn("[forum-points] balance fetch failed:", e);
    }
  }

  @action
  openHistory(ev) {
    ev?.preventDefault?.();
    ev?.stopPropagation?.();

    if (this.isError) {
      this.load({ force: true });
      return;
    }

    if (!this.userId) {
      return;
    }

    this.modal.show(WalletHistoryModal, {
      model: { discourseId: this.userId, username: this.username },
    });
  }

  <template>
    <button
      type="button"
      class={{if this.isError "forum-points forum-points--error" "forum-points"}}
      data-testid="forum-points-balance"
      title={{this.title}}
      aria-label={{this.ariaLabel}}
      {{on "click" this.openHistory}}
    >
      <span class="forum-points__label">PTS</span>
      {{#if this.isLoading}}
        <span class="forum-points__loading">...</span>
      {{else if this.isError}}
        <span class="forum-points__error">重试</span>
      {{else}}
        <span class="forum-points__value">{{this.formattedBalance}}</span>
        <span class="forum-points__unit">pts</span>
        {{#if this.activationLabel}}
          <span class="forum-points__state">{{this.activationLabel}}</span>
        {{/if}}
      {{/if}}
    </button>
  </template>
}
