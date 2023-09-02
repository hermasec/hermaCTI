$(document).ready(function() {

  checkall('contact-check-all', 'contact-chkbox');

  $('#input-search').on('keyup', function() {
    var rex = new RegExp($(this).val(), 'i');
      $('.searchable-items .items:not(.items-header-section)').hide();
      $('.searchable-items .items:not(.items-header-section)').filter(function() {
          return rex.test($(this).text());
      }).show();
  });

  $('.view-grid').on('click', function(event) {
    event.preventDefault();
    /* Act on the event */

    $(this).parents('.switch').find('.view-list').removeClass('active-view');
    $(this).addClass('active-view');

    $(this).parents('.searchable-container').removeClass('list');
    $(this).parents('.searchable-container').addClass('grid');

    $(this).parents('.searchable-container').find('.searchable-items').removeClass('list');
    $(this).parents('.searchable-container').find('.searchable-items').addClass('grid');

  });

  $('.view-list').on('click', function(event) {
    event.preventDefault();
    /* Act on the event */
    $(this).parents('.switch').find('.view-grid').removeClass('active-view');
    $(this).addClass('active-view');

    $(this).parents('.searchable-container').removeClass('grid');
    $(this).parents('.searchable-container').addClass('list');

    $(this).parents('.searchable-container').find('.searchable-items').removeClass('grid');
    $(this).parents('.searchable-container').find('.searchable-items').addClass('list');
  });

  $('#btn-add-contact').on('click', function(event) {
    $('#addContactModal #btn-add').show();
    $('#addContactModal #btn-edit').hide();
    $('#addContactModal').modal('show');
  })

function editContact() {
  $('.edit').on('click', function(event) {
    $('#addContactModal').modal('show');
  })
}

editContact()

})