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

    function setupGenerateAndCopy(genBtnId, copyBtnId, inputId, size) {
        var genBtn = document.getElementById(genBtnId);
        if (genBtn) {
            genBtn.addEventListener("click", function () {
                var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_.-/()[]<>+~?=";
                var arr = new Uint8Array(size);
                crypto.getRandomValues(arr);
                var val = "";
                for (var i = 0; i < arr.length; i++) {
                    val += chars[arr[i] % chars.length];
                }
                document.getElementById(inputId).value = val;
            });
        }
        var copyBtn = document.getElementById(copyBtnId);
        if (copyBtn) {
            copyBtn.addEventListener("click", function () {
                var input = document.getElementById(inputId);
                if (input && input.value) {
                    navigator.clipboard.writeText(input.value).then(function () {
                        showToast(copyBtn.dataset.toast || "Kopiert");
                    });
                }
            });
        }
    }

    setupGenerateAndCopy("btn-generate-secret", "btn-copy-secret", "client_secret", 32);
    setupGenerateAndCopy("btn-generate-password", "btn-copy-password", "password", 16);

    document.querySelectorAll("form[method='POST']:not(.no-spinner)").forEach(function (form) {
        form.addEventListener("submit", function () {
            form.querySelectorAll("button[type='submit']").forEach(function (btn) {
                btn.disabled = true;
                var label = btn.textContent;
                btn.innerHTML = '<span class="btn-spinner"></span> ' + label.trim();
            });
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
