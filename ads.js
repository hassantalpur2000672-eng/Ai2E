// ============================================================
// ADS.JS — Sirf yahan script paste karo, sab users ko jayegi
// ⚡ DATABASE SE ADS NAHI AATE — seedha yahan paste karo
// ============================================================


// ====================================================================
//  SOCIAL BAR AD
//  Adsterra / koi bhi network ka Social Bar script yahan paste karo
//  Sticky rahegi — screen par hamesha nazar ayegi
// ====================================================================

const SOCIAL_BAR_SCRIPT = `
<script src="https://pl29342089.profitablecpmratenetwork.com/e4/3b/9b/e43b9ba24a13948e1891c795dcb6715b.js"></script>
`;


// ====================================================================
//  NATIVE BANNER AD
//  Adsterra / koi bhi network ka Native Banner script yahan paste karo
//  Page ke footer mein show hogi
// ====================================================================

/*const NATIVE_BANNER_SCRIPT = `
<script async="async" data-cfasync="false" src="https://pl29342088.profitablecpmratenetwork.com/f060f56d36d7ed6e6c8161b8f7ec4599/invoke.js"></script>
<div id="container-f060f56d36d7ed6e6c8161b8f7ec4599"></div>
`;*/


// ============================================================
// NEECHE KUCH MAT CHHEDNA — KHUD KAAM KARTA HAI
// ============================================================

(function () {
  const socialCode = SOCIAL_BAR_SCRIPT.replace(/<!--[\s\S]*?-->/g, '').trim();
  if (socialCode) injectSocialBar(socialCode);

  const nativeCode = NATIVE_BANNER_SCRIPT.replace(/<!--[\s\S]*?-->/g, '').trim();
  if (nativeCode) injectNativeBanner(nativeCode);
})();

function injectSocialBar(code) {
  if (document.getElementById('ad-social-bar')) return;
  const bar = document.createElement('div');
  bar.id = 'ad-social-bar';
  bar.style.cssText = 'position:fixed;bottom:0;left:0;width:100%;z-index:99999;';
  runCode(code, bar);
  if (bar.children.length > 0) document.body.appendChild(bar);
}

function injectNativeBanner(code) {
  if (document.getElementById('ad-footer-native')) return;
  const wrap = document.createElement('div');
  wrap.id = 'ad-footer-native';
  wrap.style.cssText = 'width:100%;text-align:center;padding:8px 0;margin-top:8px;';
  runCode(code, wrap);
  document.body.appendChild(wrap);
}

function runCode(code, container) {
  if (!code || !code.trim()) return;
  const tmp = document.createElement('div');
  tmp.innerHTML = code;
  tmp.querySelectorAll('script').forEach(old => {
    const s = document.createElement('script');
    if (old.src) {
      s.src = old.src;
      s.async = true;
      if (old.getAttribute('data-cfasync') !== null) s.setAttribute('data-cfasync', 'false');
    } else {
      s.textContent = old.textContent;
    }
    document.head.appendChild(s);
  });
  tmp.querySelectorAll(':not(script)').forEach(el => {
    container.appendChild(el.cloneNode(true));
  });
}
