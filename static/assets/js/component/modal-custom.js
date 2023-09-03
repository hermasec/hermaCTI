function addProgressBar (){
    return `
<p id="progressLabel" class="font-italic text-black-50">درحال آپلود فایل...</p>
<div class="progress br-30 mt-5">
    <div class="progress-bar bg-primary" role="progressbar" style="width: 0%" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100"></div>
</div>
`;
}