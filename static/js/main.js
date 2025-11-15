$(function(){
  $('#searchInput, #searchInput2').on('input', function(){
    const q = $(this).val();
    $.getJSON('/api/items', {q:q}, function(data){
      const tableBody = $('#itemsTable');
      if(tableBody.length){
        tableBody.empty();
        data.forEach(function(i){
          const status = (i.quantity==0) ? '<span class="badge bg-danger">Out of Stock</span>' : (i.quantity<=5? '<span class="badge bg-primary">Low Stock</span>' : '<span class="badge bg-secondary">In Stock</span>');
          tableBody.append(`<tr><td>${i.name}</td><td>${i.category||''}</td><td>${i.quantity}</td><td>₹${i.price}</td><td>${status}</td><td></td></tr>`);
        });
      }
    });
  });

  $('#recordTx').on('click', function(){
    const payload = {
      item_id: $('#txItem').val(),
      type: $('#txType').val(),
      quantity: $('#txQty').val(),
      recipient: $('#txRecipient').val()
    };
    $.ajax({
      url: '/api/transaction',
      method: 'POST',
      contentType: 'application/json',
      data: JSON.stringify(payload),
      success: function(){
        $('#txMsg').html('<div class="alert alert-success">Transaction recorded</div>');
      },
      error: function(xhr){
        $('#txMsg').html('<div class="alert alert-danger">'+(xhr.responseJSON?.error || 'Error')+'</div>');
      }
    });
  });
});
