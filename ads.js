// ============================================================
// ADS.JS — Sirf yahan script paste karo, sab users ko jayegi
// Database mein save hogi, har user ko automatically milegi
// ============================================================


// ====================================================================
//  SOCIAL BAR AD
//  Adsterra / koi bhi network ka Social Bar script yahan paste karo
//  Sticky rahegi — screen par hamesha nazar ayegi
//  Kuch nahi lagana: bas script paste karo aur GitHub push karo
// ====================================================================

const SOCIAL_BAR_SCRIPT = `

<!-- YAHAN SOCIAL BAR SCRIPT PASTE KARO -->



`;


// ====================================================================
//  NATIVE BANNER AD
//  Adsterra / koi bhi network ka Native Banner script yahan paste karo
//  Page ke footer mein show hogi — content block nahi karega
//  Kuch nahi lagana: bas script paste karo aur GitHub push karo
// ====================================================================

const NATIVE_BANNER_SCRIPT = `

<!-- YAHAN NATIVE BANNER SCRIPT PASTE KARO -->



`;


// ============================================================
// NEECHE KUCH MAT CHHEDNA — KHUD KAAM KARTA HAI
// ============================================================

(function () {
  const page = location.pathname.split('/').pop().replace('.html', '') || 'index';

  // Social Bar inject karo
  const socialCode = SOCIAL_BAR_SCRIPT.replace(/<!--[\s\S]*?-->/g, '').trim();
  if (socialCode) {
    injectSocialBar(socialCode);
  }

  // Native Banner inject karo
  const nativeCode = NATIVE_BANNER_SCRIPT.replace(/<!--[\s\S]*?-->/g, '').trim();
  if (nativeCode) {
    injectNativeBanner(nativeCode);
  }

})();


// Social Bar — fixed sticky, screen ke neeche
function injectSocialBar(code) {
  if (document.getElementById('ad-social-bar')) return;
  const bar = document.createElement('div');
  bar.id = 'ad-social-bar';
  bar.style.cssText = 'position:fixed;bottom:0;left:0;width:100%;z-index:99999;';
  runCode(code, bar);
  if (bar.children.length > 0) document.body.appendChild(bar);
}

// Native Banner — body ke ekdum end mein
function injectNativeBanner(code) {
  if (document.getElementById('ad-footer-native')) return;
  const wrap = document.createElement('div');
  wrap.id = 'ad-footer-native';
  wrap.style.cssText = 'width:100%;text-align:center;padding:8px 0;margin-top:8px;';
  runCode(code, wrap);
  document.body.appendChild(wrap);
}

// Script execute karo + HTML inject karo
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
