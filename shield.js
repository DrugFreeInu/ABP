/* ==========================================================
   DFI UNIVERSAL SHIELD
   Static GitHub Edition
   Lightweight friction layer
========================================================== */

(function(){

    const Shield = {
        score: 0,
        signals: 0,
        flags: new Set(),
        powSolved: false,

        penalize(r,w=1){
            if(!this.flags.has(r)){
                this.flags.add(r);
                this.score += w;
            }
        },

        reward(){ this.signals++; }
    };

    /* ===== ENVIRONMENT ===== */

    if(navigator.webdriver) Shield.penalize("webdriver",5);
    if(/Headless|Phantom|Slimer/i.test(navigator.userAgent))
        Shield.penalize("headless_ua",5);
    if(!navigator.languages?.length)
        Shield.penalize("no_languages",2);
    if(navigator.plugins && navigator.plugins.length===0)
        Shield.penalize("no_plugins",2);

    Shield.reward();

    /* ===== CANVAS FINGERPRINT ===== */

    (async()=>{
        try{
            const c=document.createElement("canvas");
            const ctx=c.getContext("2d");
            ctx.font="14px Arial";
            ctx.fillText("DFI_SECURE",10,10);

            const data=c.toDataURL();
            await crypto.subtle.digest(
                "SHA-256",
                new TextEncoder().encode(data)
            );

            Shield.reward();
        }catch{
            Shield.penalize("canvas_error",3);
        }
    })();

    /* ===== LIGHTWEIGHT PROOF OF WORK ===== */

    (async()=>{
        const encoder=new TextEncoder();
        for(let nonce=0;nonce<2000;nonce++){
            const hash=await crypto.subtle.digest(
                "SHA-256",
                encoder.encode("DFI"+nonce)
            );
            const hex=[...new Uint8Array(hash)]
                .map(b=>b.toString(16).padStart(2,"0"))
                .join("");

            if(hex.startsWith("000")){
                Shield.powSolved=true;
                Shield.reward();
                break;
            }
        }
    })();

    /* ===== SILENT RESULT ===== */

    setTimeout(()=>{
        window.__DFI_SHIELD__ = {
            risk: Shield.score - Shield.signals,
            flags: [...Shield.flags]
        };
    },2500);

})();
