// ============================================
// ADS.JS — Dynamic Ad Loader
// Admin panel se ads add karo — automatically yahan aayenge
// ============================================

(async function() {
  try {
    const API = 'https://ai2e.pages.dev';
    const page = location.pathname.split('/').pop().replace('.html','') || 'index';

    const res = await fetch(API + '/api/ads');
    if (!res.ok) return;
    const ads = await res.json();
    if (!Array.isArray(ads) || !ads.length) return;

    // Filter ads for this page
    const pageAds = ads.filter(ad => {
      if (!ad.is_active || ad.is_active == 0) return false;
      const pages = ad.pages ? ad.pages.split(',') : ['index','blog','policies','vision'];
      return pages.includes(page) || pages.includes('all');
    });

    if (!pageAds.length) return;

    pageAds.forEach(ad => {
      try {
        injectAd(ad);
      } catch(e) {}
    });

  } catch(e) {}
})();

function injectAd(ad) {
  const type = ad.network || ad.type || 'script';
  const code = ad.code || '';
  const url = ad.url || '';
  const position = ad.position || 'bottom';

  if (type === 'script' || type === 'native' || type === 'social' || type === 'popunder') {
    // Script/JS ads — inject directly
    if (!code) return;
    const wrap = document.createElement('div');
    wrap.innerHTML = code;
    // Execute scripts inside
    wrap.querySelectorAll('script').forEach(oldScript => {
      const newScript = document.createElement('script');
      if (oldScript.src) {
        newScript.src = oldScript.src;
        newScript.async = true;
        if (oldScript.getAttribute('data-cfasync') !== null) {
          newScript.setAttribute('data-cfasync', 'false');
        }
      } else {
        newScript.textContent = oldScript.textContent;
      }
      document.head.appendChild(newScript);
    });
    // Append non-script elements
    const nonScripts = wrap.querySelectorAll(':not(script)');
    if (nonScripts.length) {
      const container = document.createElement('div');
      container.style.cssText = 'text-align:center;margin:10px 0;';
      nonScripts.forEach(el => container.appendChild(el.cloneNode(true)));
      insertByPosition(container, position);
    }

  } else if (type === 'banner') {
    if (!url && !code) return;
    const wrap = document.createElement('div');
    wrap.style.cssText = 'text-align:center;margin:12px 0;';
    if (code) {
      wrap.innerHTML = code;
    } else {
      wrap.innerHTML = `<a href="${url}" target="_blank" rel="noopener"><img src="${ad.imgUrl||url}" style="max-width:100%;border-radius:8px;" alt="Ad"/></a>`;
    }
    insertByPosition(wrap, position);

  } else if (type === 'iframe') {
    if (!url) return;
    const wrap = document.createElement('div');
    wrap.style.cssText = 'text-align:center;margin:12px 0;';
    wrap.innerHTML = `<iframe src="${url}" width="${ad.width||'300'}" height="${ad.height||'250'}" style="border:none;max-width:100%;" scrolling="no"></iframe>`;
    insertByPosition(wrap, position);

  } else if (type === 'smartlink') {
    if (!url) return;
    const wrap = document.createElement('div');
    wrap.style.cssText = 'text-align:center;margin:12px 0;';
    wrap.innerHTML = `<a href="${url}" target="_blank" rel="noopener" style="display:inline-block;padding:12px 24px;background:#00ff88;color:#030712;border-radius:8px;font-weight:700;text-decoration:none;">Visit Now →</a>`;
    insertByPosition(wrap, position);
  }
}

function insertByPosition(el, position) {
  if (position === 'top') {
    document.body.insertBefore(el, document.body.firstChild);
  } else if (position === 'middle') {
    const mid = Math.floor(document.body.children.length / 2);
    const refEl = document.body.children[mid];
    if (refEl) document.body.insertBefore(el, refEl);
    else document.body.appendChild(el);
  } else {
    document.body.appendChild(el);
  }
}
