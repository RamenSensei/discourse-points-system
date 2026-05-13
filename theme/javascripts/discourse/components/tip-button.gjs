// Glimmer post-menu button for Discourse 2026.x.
//
// Receives @post from the menu's value transformer registration. We use
// @translatedLabel/@translatedTitle to avoid Discourse's i18n key resolution,
// which would otherwise look for `forum_points.tip` in the core locale
// (not in our theme's locale namespace).

import Component from "@glimmer/component";
import { action } from "@ember/object";
import { service } from "@ember/service";
import DButton from "discourse/components/d-button";
import TipModal from "./tip-modal";

export default class PostMenuTipButton extends Component {
  @service modal;
  @service currentUser;

  get post() { return this.args.post; }

  get hide() {
    if (!this.currentUser) return true;
    if (!this.post) return true;
    if (!Number.isInteger(Number(this.post.user_id)) || Number(this.post.user_id) <= 0) return true;
    if (this.post.deleted_at) return true;
    return this.post.user_id === this.currentUser.id;
  }

  get title() {
    return `打赏 @${this.post?.username ?? ""}`;
  }

  @action
  openTipModal() {
    if (this.hide) return;
    this.modal.show(TipModal, {
      model: {
        targetId:       Number(this.post.user_id),
        targetUsername: this.post.username,
        targetPostId:   this.post.id,
      },
    });
  }

  <template>
    {{#unless this.hide}}
      <DButton
        class="btn-flat post-action-menu__points-tip points-tip-button"
        @icon="gift"
        @translatedLabel="打赏"
        @translatedTitle={{this.title}}
        @action={{this.openTipModal}}
      />
    {{/unless}}
  </template>
}
