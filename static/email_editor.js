function isQuillEmpty(quill) {
  if ((quill.getContents()['ops'] || []).length !== 1) { return false }
  return quill.getText().trim().length === 0
}

document.addEventListener('DOMContentLoaded', function () {
    var editorContainer = document.getElementById('editor');
    if (!editorContainer) return;

    var quill = new Quill('#editor', {
        theme: 'snow',
        modules: {
            toolbar: [
                [{ header: [1, 2, 3, false] }],
                ['bold', 'italic', 'underline', 'strike'],
                [{ color: [] }, { background: [] }],
                [{ list: 'ordered' }, { list: 'bullet' }],
                ['link'],
                ['clean']
            ]
        }
    });

    // Load existing content
    var bodyHtml = document.getElementById('body_html');
    if (bodyHtml && bodyHtml.value) {
        quill.root.innerHTML = bodyHtml.value;
    }

    // Sync to hidden field on submit
    var form = editorContainer.closest('form');
    if (form) {
        form.addEventListener('submit', function () {
            bodyHtml.value = isQuillEmpty(quill) ? "" : quill.root.innerHTML;
        });
    }
});
