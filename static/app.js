function showToast(message) {
    const toast = document.createElement("div");
    toast.className = "toast";
    toast.textContent = message;
    document.body.appendChild(toast);
    requestAnimationFrame(function () { toast.classList.add("toast-visible"); });
    setTimeout(function () {
        toast.classList.remove("toast-visible");
        setTimeout(function () { toast.remove(); }, 300);
    }, 2000);
}

document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll(".delete-form").forEach(function (form) {
        form.addEventListener("submit", function (e) {
            if (!confirm(form.dataset.confirm || "Wirklich löschen?")) {
                e.preventDefault();
            }
        });
    });

    const genBtn = document.getElementById("btn-generate-secret");
    if (genBtn) {
        genBtn.addEventListener("click", function () {
            const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_.-/()[]<>+~?=";
            const arr = new Uint8Array(32);
            crypto.getRandomValues(arr);
            var secret = "";
            for (var i = 0; i < arr.length; i++) {
                secret += chars[arr[i] % chars.length];
            }
            document.getElementById("client_secret").value = secret;
        });
    }

    const copyBtn = document.getElementById("btn-copy-secret");
    if (copyBtn) {
        copyBtn.addEventListener("click", function () {
            const input = document.getElementById("client_secret");
            if (input && input.value) {
                navigator.clipboard.writeText(input.value).then(function () {
                    showToast(copyBtn.dataset.toast || "Kopiert");
                });
            }
        });
    }

    document.querySelectorAll("form[method='POST']:not(.no-spinner)").forEach(function (form) {
        form.addEventListener("submit", function () {
            var btn = form.querySelector("button[type='submit']:focus") || form.querySelector("button[type='submit'].btn-primary") || form.querySelector("button[type='submit']");
            if (!btn || btn.disabled) return;
            btn.disabled = true;
            var label = btn.textContent;
            btn.innerHTML = '<span class="btn-spinner"></span> ' + label.trim();
        });
    });

    document.querySelectorAll(".utc-time").forEach(function (el) {
        const raw = el.dataset.utc;
        if (!raw) return;
        const d = new Date(raw.endsWith("Z") ? raw : raw + "Z");
        if (isNaN(d.getTime())) return;
        const formatted = d.toLocaleString();
        if (el.classList.contains("lock-icon")) {
            el.title = (el.title ? el.title + " " : "") + formatted;
        } else if (el.tagName === "INPUT") {
            el.value = formatted;
        } else {
            el.textContent = formatted;
        }
    });
});
