window.addEventListener('load', function()
{
    var xhr = null;

    getXmlHttpRequestObject = function()
    {
        if(!xhr)
        {
            xhr = new XMLHttpRequest();
        }
        return xhr;
    };
   
    updateLiveData = function()
    {
        var url = 'http://localhost:5000/cart';
        xhr = getXmlHttpRequestObject();

        xhr.onreadystatechange = eventHandler;

        xhr.open("GET", url, true);

        xhr.send(null);
    };


    function eventHandler(){

        if(xhr.readyState == 4 && xhr.status == 200){

            data = document.getElementById('cnt2');
            data.innerHTML = xhr.responseText;

            // setTimeout(updateLiveData(), 1000);
        }
    }

    
    updateLiveData();
});


