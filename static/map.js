class Map {
  constructor() {
    this.map = null;
    this.initMap();
  }

  async initMap() {
    const mapOptions = {
      center: { lat: -86, lng: 50 },
      zoomControl: false,
      scaleControl: true,
      fullscreenControl: false,
      mapTypeControl: false,
      tilt: 0,
      gestureHandling: 'greedy',
      maxZoom: 21,
      minZoom: 0,
      streetViewControl: true
    };

    const { Map } = await google.maps.importLibrary("maps");
    this.map = new Map(document.getElementById("map"), {
      mapTypeId: 'satellite',
      mapTypeId: 'hybrid',
      center: { lat: 25, lng: -10 },
      zoomControl: false,
      scaleControl: true,
      fullscreenControl: false,
      mapTypeControl: false,
      tilt: 0,
      gestureHandling: 'greedy',
      maxZoom: 21,
      minZoom: 3,
      streetViewControl: true,
      zoom: 3,
    });

    this.setupAutocomplete();
  }

  setupAutocomplete() {
    const input = document.getElementById('google-maps-search');
    const autocomplete = new google.maps.places.Autocomplete(input);
    autocomplete.bindTo('bounds', this.map);

    autocomplete.addListener('place_changed', () => {
      const place = autocomplete.getPlace();
      console.log(place);
      if (!place.geometry) {
        console.log("No details available for input: '" + place.name + "'");
        return;
      }
      if (place.geometry.viewport) {
        this.map.fitBounds(place.geometry.viewport);
      } else {
        this.map.setCenter(place.geometry.location);
        this.map.setZoom(17);
      }
    });

    $(input).on('click', () => {
      input.value = "";
    });

    if (input.value.trim() !== "") {
      input.value = "";
    }
  }
}


$(document).ready(() => {
  const map = new Map();
})

