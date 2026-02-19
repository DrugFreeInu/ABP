<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ASI Sentinel Enterprise v1</title>
</head>
<body style="display:none">

<script>
/*
============================================================================
ASI SENTINEL ENTERPRISE v1.0.0
----------------------------------------------------------------------------

Design Principles:
- Deterministic
- Non-destructive
- Backend authoritative
- Replay resistant
- Scalable
- Observable
- Safe for production

No infinite loops.
No memory abuse.
No CPU locking.
No browser freezing.

All enforcement MUST occur server-side.
============================================================================
*/

const ASISentinel = (() => {

    const VERSION = "1.0.0";
    const START_TIME = performance.now();

    const state = {
        score: 0,
        signals: 0,
        flags: new Set(),
        behavioralEntropy: 0,
        timingVariance: 0,
        workerIntegrity: false,
        renderHash: null,
        sessionNonce: null
    };

    /* ================= CORE ================= */

    function penalize(flag, weight = 1){
        if(!state.flags.has(flag)){
            state.flags.add(flag);
            state.score += weight;
        }
    }

    function reward(){
        state.signals++;
    }

    /* ================= ENVIRONMENT ================= */

    function environmentChecks(){

        if(navigator.webdriver) penalize("webdriver",5);

        if(/Headless|Phantom|Slimer/i.test(navigator.userAgent))
            penalize("headless_ua",5);

        if(!navigator.languages?.length)
            penalize("no_languages",2);

        if(navigator.plugins && navigator.plugins.length === 0)
            penalize("no_plugins",2);

        if(window.outerWidth === 0 || window.outerHeight === 0)
            penalize("zero_viewport",3);

        reward();
    }

    /* ================= RENDER HASH ================= */

    async function renderFingerprint(){

        try{
            const canvas = document.createElement("canvas");
            const ctx = canvas.getContext("2d");

            ctx.font = "14px Arial";
            ctx.fillText("ASI_SENTINEL_V1", 10, 10);

            const data = canvas.toDataURL();

            const hashBuffer = await crypto.subtle.digest(
                "SHA-256",
                new TextEncoder().encode(data)
            );

            state.renderHash = [...new Uint8Array(hashBuffer)]
                .map(b=>b.toString(16).padStart(2,"0"))
                .join("");

            reward();

        } catch {
            penalize("render_error",3);
        }
    }

    /* ================= BEHAVIORAL MODEL ================= */

    function behavioralMonitor(){

        let movements = [];
        let lastTime = 0;

        document.addEventListener("mousemove",(e)=>{

            const now = performance.now();

            if(lastTime && now - lastTime < 5)
                penalize("impossible_mouse_speed",2);

            movements.push({x:e.clientX,y:e.clientY,t:now});
            lastTime = now;

            if(movements.length > 40){

                let entropy = 0;

                for(let i=2;i<movements.length;i++){
                    const a=movements[i-2];
                    const b=movements[i-1];
                    const c=movements[i];

                    entropy += Math.abs(
                        (b.x-a.x)*(c.y-b.y) -
                        (b.y-a.y)*(c.x-b.x)
                    );
                }

                state.behavioralEntropy = entropy;

                if(entropy < 40)
                    penalize("low_entropy_path",3);
                else
                    reward();

                movements = movements.slice(-15);
            }

        },{passive:true});
    }

    /* ================= TIMING ================= */

    function timingCheck(){

        const base = performance.now();

        setTimeout(()=>{
            const drift = performance.now() - base;

            state.timingVariance = drift;

            if(drift < 0) penalize("negative_time",3);
            if(drift < 8) penalize("timer_anomaly",1);

            reward();

        },250);
    }

    /* ================= WORKER INTEGRITY ================= */

    function workerCheck(){

        try{
            const blob = new Blob([
                `self.onmessage=e=>e.ports[0].postMessage("ok");`
            ],{type:"application/javascript"});

            const worker = new Worker(URL.createObjectURL(blob));
            const channel = new MessageChannel();

            let responded = false;

            channel.port1.onmessage = ()=>{
                responded = true;
                state.workerIntegrity = true;
                reward();
            };

            worker.postMessage(null,[channel.port2]);

            setTimeout(()=>{
                if(!responded)
                    penalize("worker_fail",3);
                worker.terminate();
            },800);

        } catch {
            penalize("worker_error",3);
        }
    }

    /* ================= SESSION NONCE ================= */

    function generateSessionNonce(){
        state.sessionNonce =
            crypto.getRandomValues(new Uint32Array(4)).join("-");
    }

    /* ================= PAYLOAD ================= */

    function buildPayload(){

        return {
            engine: "ASI_SENTINEL_ENTERPRISE",
            version: VERSION,
            timestamp: Date.now(),
            runtime: performance.now() - START_TIME,
            score: state.score,
            signals: state.signals,
            flags: [...state.flags],
            renderHash: state.renderHash,
            behavioralEntropy: state.behavioralEntropy,
            timingVariance: state.timingVariance,
            workerIntegrity: state.workerIntegrity,
            nonce: state.sessionNonce
        };
    }

    /* ================= INIT ================= */

    async function init(){

        generateSessionNonce();
        environmentChecks();
        behavioralMonitor();
        timingCheck();
        workerCheck();
        await renderFingerprint();

        return buildPayload();
    }

    return {
        init,
        buildPayload
    };

})();

/* ================= AUTO START ================= */

(async ()=>{
    const payload = await ASISentinel.init();

    /*
    Example backend call:

    fetch("/risk",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify(payload)
    });

    Backend Responsibilities:
    - Verify nonce uniqueness
    - Bind IP
    - Apply ASN / TLS fingerprint scoring
    - Detect replay
    - Issue signed short-lived access token
    */

    document.body.style.display = "block";

    console.log(
        "%cASI Sentinel Enterprise Active",
        "color:#00ff88;font-weight:bold;"
    );
})();
</script>

</body>
</html>
