import { apiInitializer } from "discourse/lib/api";
import PostAvatarBalance from "../components/post-avatar-balance";
import PostMenuTipButton from "../components/tip-button";
import { walletAccountUrl } from "../lib/wallet-api";

const TAG = "[forum-points]";
let initialized = false;

function looksDuplicateError(err) {
  return /already|duplicate|exist/i.test(String(err?.message ?? err));
}

function addTipButton(dag) {
  try {
    dag.add("points-tip", PostMenuTipButton, { before: "share" });
  } catch (err1) {
    if (looksDuplicateError(err1)) {
      return;
    }

    try {
      dag.add("points-tip", PostMenuTipButton);
    } catch (err2) {
      if (!looksDuplicateError(err2)) {
        // eslint-disable-next-line no-console
        console.error(TAG, "post-menu registration failed:", err1, err2);
      }
    }
  }
}

export default apiInitializer("1.13.0", (api) => {
  if (initialized) {
    return;
  }
  initialized = true;

  // Modern Glimmer post-menu uses a value transformer. Entries are Glimmer
  // component CLASSES — passing a plain config object crashes Ember with
  // "Cannot read properties of null (reading 'manager')".
  try {
    if (typeof api.registerValueTransformer === "function") {
      api.registerValueTransformer("post-menu-buttons", ({ value: dag }) => {
        addTipButton(dag);
      });
    } else {
      // eslint-disable-next-line no-console
      console.warn(TAG, "api.registerValueTransformer missing; post-menu button not registered");
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error(TAG, "transformer registration failed:", e);
  }

  try {
    if (typeof api.renderAfterWrapperOutlet === "function") {
      api.renderAfterWrapperOutlet("post-avatar", PostAvatarBalance);
    } else {
      // eslint-disable-next-line no-console
      console.warn(TAG, "api.renderAfterWrapperOutlet missing; avatar balance not registered");
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error(TAG, "post-avatar registration failed:", e);
  }

  try {
    const currentUser = api.getCurrentUser?.();
    if (currentUser?.id && typeof api.addCommunitySectionLink === "function") {
      api.addCommunitySectionLink({
        name: "forum-points-wallet",
        href: walletAccountUrl(currentUser.id),
        title: "查看我的 PTS 钱包和流水",
        text: "我的钱包",
      });
    }
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error(TAG, "wallet sidebar link registration failed:", e);
  }
});
