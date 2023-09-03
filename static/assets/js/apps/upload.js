/* Functions */
function virusTotal(hash) {
    return new Promise(function (resolve, reject) {
        var formData = new FormData();
        formData.append('hash', hash);

        $.ajax({
            url: '/api/file/virustotal/',
            type: 'POST',
            data: formData,
            processData: false, // Prevent jQuery from processing the data
            contentType: false, // Let the browser set the content type
            success: function (response) {
                resolve(response[0]);
            },
            error: function (xhr, status, error) {
                console.error('Error:', error);
                reject(error);
            }
        });
    });
}


function hybrid(hash) {
    return new Promise(function (resolve, reject) {
        var formData = new FormData();
        formData.append('hash', hash);

        $.ajax({
            url: '/api/file/hybrid/',
            type: 'POST',
            data: formData,
            processData: false, // Prevent jQuery from processing the data
            contentType: false, // Let the browser set the content type
            success: function (response) {
                resolve(response[0]);
            },
            error: function (xhr, status, error) {
                console.error('Error:', error);
                reject(error);
            }
        });
    });
}


function otx(hash) {
    return new Promise(function (resolve, reject) {
        var formData = new FormData();
        formData.append('hash', hash);

        $.ajax({
            url: '/api/file/otx/',
            type: 'POST',
            data: formData,
            processData: false, // Prevent jQuery from processing the data
            contentType: false, // Let the browser set the content type
            success: function (response) {
                resolve(response[0]);
            },
            error: function (xhr, status, error) {
                console.error('Error:', error);
                reject(error);
            }
        });
    });
}

function intezer(hash) {
    return new Promise(function (resolve, reject) {
        var formData = new FormData();
        formData.append('hash', hash);

        $.ajax({
            url: '/api/file/intezer/',
            type: 'POST',
            data: formData,
            processData: false, // Prevent jQuery from processing the data
            contentType: false, // Let the browser set the content type
            success: function (response) {
                resolve(response[0]);
            },
            error: function (xhr, status, error) {
                console.error('Error:', error);
                reject(error);
            }
        });
    });
}

$(document).ready(function () {

    /* Events */
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

    $('#btn-scan').on('click', function () {
        var additionalPath = 'uploads\\'; 
        var fileInput = $('#uploader')[0].files[0];
        

        if (fileInput) {
            var filename = fileInput.name;
            var fullPath = additionalPath + filename;
            var formData = new FormData();
            formData.append('filename', fullPath);


            $(".contact-name").html(addProgressBar());

            $.ajax({
                url: '/api/file/info/', // Replace with your server endpoint
                type: 'POST', // Use the appropriate HTTP method (POST, PUT, etc.)
                data: formData,
                contentType: false,
                processData: false,
                xhr: function () {
                    var xhr = new window.XMLHttpRequest();
                    // Listen to the progress event
                    xhr.upload.addEventListener("progress", function (evt) {
                        if (evt.lengthComputable) {
                            var percentComplete = ((evt.loaded / evt.total) * 100) / 5;
                            if (percentComplete < 20) {
                                // Update the progress bar (assuming you have an element with class "progress-bar")
                                $(".progress-bar").width(percentComplete + "%");
                            } else if (percentComplete === 20) {
                                $("#progressLabel").text("فایل آپلود شد.");
                                $(".progress-bar").width(percentComplete + "%");
                            }
                        }
                    }, false);

                    return xhr;
                },
                success: function (response) {
                    /* Virustotal */
                    setTimeout(function () {
                        $(".progress-bar").width("20%");
                        $("#progressLabel").text("درحال دریافت اطلاعات از Virustotal...");

                        virusTotal(response[0]["hash"])
                            .then(function (result) {
                                $(".progress-bar").width("40%");
                                $("#progressLabel").text("درحال دریافت اطلاعات از Hybrid...");

                                hybrid(response[0]["hash"])
                                    .then(function (result) {
                                        $(".progress-bar").width("60%");
                                        $("#progressLabel").text("درحال دریافت اطلاعات از OTX...");

                                        otx(response[0]["hash"])
                                            .then(function (result) {
                                                $(".progress-bar").width("80%");
                                                $("#progressLabel").text("درحال دریافت اطلاعات از OTX...");

                                                intezer(response[0]["hash"])
                                                    .then(function (result) {
                                                        $(".progress-bar").width("100%");
                                                        $("#progressLabel").text("درحال دریافت اطلاعات از Intezer...");
                                                    });
                                            });
                                    });
                            });

                    }, 1000); // Initial delay (can be adjusted)


                },
                error: function (xhr, status, error) {
                    console.error('Error uploading file:', error);
                }
            });

        } else {
            console.log('No file selected.');
        }
    });
});