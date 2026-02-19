<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Nexus Shield Enterprise Client</title>
</head>
<body>

<script>
/*
=====================================================================
NEXUS SHIELD v2.0 — ENTERPRISE CLIENT ENGINE
=====================================================================

Enterprise Characteristics:
- Deterministic structured payload
- Versioned engine
- Non-blocking async architecture
- Server-bound nonce integration
- WebAuthn hardware attestation hook
- Replay-safe submission model
- Backend scoring compatible
- No UI interference

=====================================================================
*/

const NexusShield = (() => {

    const ENGINE_VERSION = "2.0.0";
    const START_TIME = performance.now();

    let state = {
        score: 0,
        signals: 0,
        flags: new Set(),
        fingerprint: null,
        timingDrift: null,
        workerIntegrity: false,
        behavioralEntropy: 0,
        attestation: null
    };

    /* ================= SCORING ================= */

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
        if(/Headless|Phantom/i.test(navigator.userAgent))
            penalize("headless_ua",5);

        if(!navigator.languages?.length)
            penalize("no_languages",2);

        if(navigator.plugins && navigator.plugins.length === 0)
            penalize("no_plugins",2);

        if(window.outerWidth === 0 || window.outerHeight === 0)
            penalize("zero_viewport",3);

        reward();
    }

    /* ================= RENDER FINGERPRINT ================= */

    async function renderingFingerprint(){

        try{
            const canvas = document.createElement("canvas");
            const ctx = canvas.getContext("2d");
            ctx.font = "16px Arial";
            ctx.fillText("NEXUS_RENDER_V2", 10, 10);

            const data = canvas.toDataURL();

            const hashBuffer = await crypto.subtle.digest(
                "SHA-256",
                new TextEncoder().encode(data)
            );

            state.fingerprint = [...new Uint8Array(hashBuffer)]
                .map(b=>b.toString(16).padStart(2,"0"))
                .join("");

            reward();

        }catch(e){
            penalize("render_error",3);
        }
    }

    /* ================= BEHAVIORAL PHYSICS ================= */

    function behavioralModel(){

        let points = [];
        let last = 0;

        document.addEventListener("mousemove",(e)=>{
            const now = performance.now();

            if(last && now-last < 5)
                penalize("impossible_mouse_speed",2);

            points.push({x:e.clientX,y:e.clientY,t:now});
            last = now;

            if(points.length > 40){

                let entropy = 0;

                for(let i=2;i<points.length;i++){
                    const a=points[i-2];
                    const b=points[i-1];
                    const c=points[i];

                    entropy += Math.abs(
                        (b.x-a.x)*(c.y-b.y) -
                        (b.y-a.y)*(c.x-b.x)
                    );
                }

                state.behavioralEntropy = entropy;

                if(entropy < 50)
                    penalize("low_behavioral_entropy",3);
                else
                    reward();

                points = points.slice(-15);
            }

        },{passive:true});
    }

    /* ================= TIMING INTEGRITY ================= */

    function timingIntegrity(){

        const start = performance.now();

        setTimeout(()=>{
            const delta = performance.now()-start;

            state.timingDrift = delta;

            if(delta < 0) penalize("negative_delta",3);
            if(delta < 10) penalize("timer_anomaly",1);

            reward();

        },250);
    }

    /* ================= WORKER ISOLATION ================= */

    async function workerIntegrityCheck(){

        try{
            const code =
                `self.onmessage=e=>e.ports[0].postMessage("ok")`;

            const blob = new Blob([code],{type:"application/javascript"});
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
                    penalize("worker_failed",3);
                worker.terminate();
            },800);

        }catch(e){
            penalize("worker_error",3);
        }
    }

    /* ================= HARDWARE ATTESTATION ================= */

    async function requestAttestation(serverChallenge){

        try{
            const credential = await navigator.credentials.get({
                publicKey:{
                    challenge: serverChallenge,
                    userVerification:"required"
                }
            });

            state.attestation = credential;
            reward();

        }catch(e){
            penalize("attestation_failed",5);
        }
    }

    /* ================= PAYLOAD ================= */

    function buildPayload(){

        return {
            engineVersion: ENGINE_VERSION,
            timestamp: Date.now(),
            runtime: performance.now() - START_TIME,
            score: state.score,
            signals: state.signals,
            flags: [...state.flags],
            fingerprint: state.fingerprint,
            timingDrift: state.timingDrift,
            workerIntegrity: state.workerIntegrity,
            behavioralEntropy: state.behavioralEntropy,
            attestation: state.attestation
        };
    }

    /* ================= INIT ================= */

    async function init(){

        environmentChecks();
        behavioralModel();
        timingIntegrity();
        workerIntegrityCheck();
        await renderingFingerprint();

        return buildPayload();
    }

    return {
        init,
        requestAttestation,
        buildPayload
    };

})();

/* ================= AUTO START ================= */

(async ()=>{
    const payload = await NexusShield.init();

    /*
    Recommended backend call:

    fetch("/risk",{
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify(payload)
    });

    Server Responsibilities:
    - Verify nonce
    - Validate WebAuthn
    - Bind IP
    - Score risk
    - Issue short-lived signed token
    */

})();
</script>

</body>
</html>
