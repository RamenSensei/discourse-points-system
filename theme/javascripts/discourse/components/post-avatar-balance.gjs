import Component from "@glimmer/component";
import { tracked } from "@glimmer/tracking";
import { action } from "@ember/object";
import { on } from "@ember/modifier";
import { registerDestructor } from "@ember/destroyable";
import {
  BALANCE_CHANGED_EVENT,
  fetchAccount,
  formatPoints,
  invalidateBalances,
  walletAccountUrl,
} from "../lib/wallet-api";

export default class PostAvatarBalance extends Component {
  @tracked account = null;
  @tracked status = "loading"; // loading | ok | error

  _destroyed = false;
  _loadId = 0;

  static shouldRender(args) {
    const id = Number(args?.post?.user_id);
    return Number.isInteger(id) && id > 0;
  }

  constructor() {
    super(...arguments);

    this.onBalanceChanged = (event) => {
      if (!this.shouldDisplay) {
        return;
      }

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

    if (this.shouldDisplay) {
      this.load();
    }
  }

  get post() {
    return this.args.post;
  }

  get userId() {
    return Number(this.post?.user_id);
  }

  get username() {
    return this.post?.username ?? this.account?.username ?? "该用户";
  }

  get shouldDisplay() {
    return Number.isInteger(this.userId) && this.userId > 0;
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

  get isVisible() {
    return this.shouldDisplay && !this.isError;
  }

  get accountUrl() {
    return walletAccountUrl(this.userId);
  }

  get formattedBalance() {
    return formatPoints(this.account?.balance ?? 0);
  }

  get title() {
    if (this.isLoading) {
      return `正在读取 @${this.username} 的 PTS 余额`;
    }
    return `@${this.username} 的 PTS 余额 ${this.formattedBalance} pts`;
  }

  get ariaLabel() {
    return this.title;
  }

  get cssClass() {
    const classes = ["forum-points-post-balance"];
    if (this.isLoading) {
      classes.push("forum-points-post-balance--loading");
    }
    return classes.join(" ");
  }

  async load({ force = false } = {}) {
    if (!this.shouldDisplay) {
      return;
    }

    const loadId = ++this._loadId;
    this.status = "loading";

    try {
      const account = await fetchAccount(this.userId, { force });
      if (this._destroyed || loadId !== this._loadId) {
        return;
      }
      this.account = account;
      this.status = "ok";
    } catch (e) {
      if (this._destroyed || loadId !== this._loadId) {
        return;
      }
      this.status = "error";
      // eslint-disable-next-line no-console
      console.warn("[forum-points] post-avatar balance fetch failed:", e);
    }
  }

  @action
  stopPropagation(ev) {
    ev?.stopPropagation?.();
  }

  <template>
    {{#if this.isVisible}}
      <a
        class={{this.cssClass}}
        href={{this.accountUrl}}
        title={{this.title}}
        aria-label={{this.ariaLabel}}
        data-testid="forum-points-post-balance"
        {{on "click" this.stopPropagation}}
      >
        <span class="forum-points-post-balance__label">PTS</span>
        <span class="forum-points-post-balance__value">
          {{#if this.isLoading}}
            ...
          {{else if this.isOk}}
            {{this.formattedBalance}}
          {{/if}}
        </span>
      </a>
    {{/if}}
  </template>
}
