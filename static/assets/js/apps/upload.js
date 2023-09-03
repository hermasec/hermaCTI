$(document).ready(function () {
    $('.custom-file-container__custom-file__custom-file-input').on('change', function () {
        // Get the selected file name
        var fileName = $(this).val().split('\\').pop(); // Extract the file name from the input's value

        if (fileName) {
            // A file was selected
            $(".custom-file-name").text(fileName);
            $('#btn-scan').removeAttr('disabled');
        } else {
            // No file was selected (canceled)
            $(".custom-file-name").text('فایلی انتخاب نشده'); // Clear the file name
            $('#btn-scan').attr('disabled', 'disabled'); // Disable the button
        }
    });
});


$(document).ready(function () {
    $('#btn-scan').on('click', function () {
        var additionalPath = 'uploads\\'; 
        var fileInput = $('#uploader')[0].files[0];
        

        if (fileInput) {
            var filename = fileInput.name;
            var fullPath = additionalPath + filename;
            var formData = new FormData();
            formData.append('filename', fullPath);

            $(".modal-content").block({
                message: '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="feather feather-loader spin"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line></svg>',
                overlayCSS: {
                    backgroundColor: '#fff',
                    opacity: 1,
                    cursor: 'wait'
                },
                css: {
                    border: 0,
                    color: '#4361ee',
                    padding: 0,
                    backgroundColor: 'transparent'
                }
            });


            $.ajax({
                url: '/api/file/info/', // Replace with your server endpoint
                type: 'POST', // Use the appropriate HTTP method (POST, PUT, etc.)
                data: formData,
                contentType: false,
                processData: false,
                success: function (response)
                {
                    location.reload();
                },
                error: function (xhr, status, error) {
                    $(".modal-content").unblock()
                    console.error('Error uploading file:', error);
                }
            });
        } else {
            console.log('No file selected.');
        }
    });
});