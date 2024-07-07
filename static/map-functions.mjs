//let path = window.location.pathname
//let segments = path.split('/');
//let id = segments.pop(); 
//
//let markers = []
//let distanceOverlays = []
//let paths = []
//let polylines = []
//let selectedMarker = null;
//
//let streetViewTabOpened = false;
//let streetView;
//let pegmanMarker;
//
//
//function initMap() {
//  const mapOptions = {
//    center: { lat: -86, lng: 50},
//    //mapId: '174211dc9f8dbb94',
//		zoomControl: false,
//		scaleControl: true,
//		fullscreenControl: false,
//		mapTypeControl: false,
//		//mapTypeId: google.maps.MapTypeId.HYBRID,
//		tilt: 0,
//		gestureHandling: 'greedy',
//		maxZoom: 21, 
//		minZoom: 0, 
//    streetViewControl: true
//  };
//
//  const map = new google.maps.Map(document.getElementById("map"), mapOptions);
//  //const input = document.getElementById('google-maps-search');
//}
//
//initMap();
  //const autocomplete = new google.maps.places.Autocomplete(input);

  //autocomplete.bindTo('bounds', map);

  //autocomplete.addListener('place_changed', () => {
  //  const place = autocomplete.getPlace();
  //  if (!place.geometry) {
  //    console.log("No details available for input: '" + place.name + "'");
  //    return;
  //  }

  //  // If the place has a geometry, present it on the map
  //  if (place.geometry.viewport) {
  //    map.fitBounds(place.geometry.viewport);
  //  } else {
  //    map.setCenter(place.geometry.location);
  //    map.setZoom(17);
  //  }
  //});
  //const poleLocations = await loadPolePositions(id);
  //paths = await loadMidspans(id);

  //poleLocations.forEach(location => {
  //  initializeMarker(location, map);
  //})

  //if (paths.length > 0) {
  //  paths.forEach(path => {
  //    createPolyline(path, map)
  //  })
  //}

  //if (markers.length > 0) {
  //  const bounds = new google.maps.LatLngBounds();
  //  markers.forEach(marker => {
  //    bounds.extend(marker.position);
  //  });
  //  map.fitBounds(bounds);
  //}

  //const panorama = new google.maps.StreetViewPanorama(
  //  document.getElementById("pano"),
  //  {
  //    position: { lat: 42.345573, lng: -71.098326 },
  //    addressControlOptions: {
  //      position: google.maps.ControlPosition.BOTTOM_CENTER,
  //    },
  //    linksControl: false,
  //    panControl: false,
  //    enableCloseButton: false,
  //  },
  //);


  //streetView = map.getStreetView();

  //// Listen for visibility change of Street View
  //streetView.addListener('visible_changed', function() {
  //if (streetView.getVisible() && !streetViewTabOpened) {
  //  streetView.setVisible(false); // Hide Street View in the map

  //  const position = streetView.getPosition();

  //  if (position) {
  //    openStreetViewInNewTab(position.lat(), position.lng());
  //    streetViewTabOpened = true;
  //  }
  //}
//});

  //streetView.addListener('visible_changed', function() {
  //  if (streetView.getVisible() && !streetViewTabOpened) {
  //    streetView.setVisible(false); // Hide Street View in the map

  //    setiitimeout(() => {
  //    }, 1000)
  //    const position = streetView.getPosition();
  //    openStreetViewInNewTab(position.lat(), position.lng());

  //    streetViewTabOpened = true;
  //  }
  //});

  // Create Pegman marker
  //pegmanMarker = new google.maps.Marker({
  //  position: map.getCenter(),
  //  icon: {
  //    size: new google.maps.Size(34, 54),
  //    anchor: new google.maps.Point(17, 54) // Center bottom point of the marker
  //  },
  //  map: map,
  //  draggable: true,
  //  title: 'Drag me!'
  //});

  // Listen for drag end of Pegman marker
//  google.maps.event.addListener(pegmanMarker, 'dragend', function() {
//    const position = pegmanMarker.getPosition();
//    streetView.setPosition(position);
//    //streetView.setVisible(true); // Show Street View at the Pegman marker position
//  });
//
//  // Function to open Street View in a new tab
//  function openStreetViewInNewTab(lat, lng) {
//    const url = `https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=${lat},${lng}`;
//    const newTab = window.open(url, '_blank');
//  }
//}

//function handlePegmanDrag() {
//  if (!streetViewOpenedOnce) {
//    streetViewOpenedOnce = true;
//    streetView.setVisible(true); // Show Street View in the embedded map
//  }
//}
//
//function initializeMarker(location, map) {
//  //let locationLatLng = localToGeographic(location.geoPosition.x, location.geoPosition.y);
//  const position = new google.maps.LatLng(location.mapPosition.lng, location.mapPosition.lat);
//  const markerOptions = {
//    geoPosition: {
//      "x": location.geoPosition.x,
//      "y": location.geoPosition.y,
//      "z": location.geoPosition.z,
//    },
//    position: position,
//    map: map,
//    selected: false,
//    icon: MarkerIcon('aerial', false),
//    draggable: false,
//  };
//
//  const marker = new google.maps.Marker(markerOptions);
//  marker.addListener('click', (e) => handleMarkerClick(marker, map));
//  marker.addListener('dblclick', (e) => handleMarkerDblClick(marker, map));
//  markers.push(marker);
//}
//
////let numberOverlays = [];
////const overlay = addNumberOverlayForMarkers(marker, markers.length, map);
////numberOverlays.push(overlay)
//function addNumberOverlayForMarkers(marker, number, map) {
//    const overlay = new google.maps.OverlayView();
//    overlay.onAdd = function () {
//      const div = document.createElement('div');
//      div.className = 'distance-overlay';
//      div.innerHTML = `${number}`;
//      div.style.width = 'fit-content';
//      div.style.backgroundColor = 'rgba(255, 255, 255, 0.4)';
//      div.style.padding = '2px 5px';
//      div.style.borderRadius = '3px';
//      div.style.position = 'absolute';
//      this.getPanes().floatPane.appendChild(div);
//      this.div = div;
//    };
//
//    overlay.draw = function () {
//      const projection = this.getProjection();
//      const position = projection.fromLatLngToDivPixel(new google.maps.LatLng(marker.position.lat(), marker.position.lng()));
//      const div = this.div;
//      div.style.left = position.x + 'px';
//      div.style.top = position.y + 'px';
//    };
//
//    overlay.onRemove = function () {
//      this.div.parentNode.removeChild(this.div);
//      this.div = null;
//    };
//
//    overlay.setMap(map);
//    return overlay;
//}
//
//async function loadMidspans(id) {
//  try {
//    const response = await fetch(`/midspans/${id}`);
//    if (!response.ok) {
//      throw new Error("Failed to fetch midspans");
//    }
//    const data = await response.json();
//    return data;
//	} catch (error) {
//		console.error('Error fetching wire paths:', error);
//	}
//}
//
//async function loadPolePositions(id) {
//	try {
//    const response = await fetch(`http://localhost:3000/getMarkersAndPaths/${id}`)
//    
//    if (!response.ok) {
//      throw new Error("Failed to fetch job saved status");
//    }
//    const data = await response.json();
//    return data;
//    //return { markers : data[0].markers, paths : data[0].paths, saved: true };
//
//	} catch (error) {
//		console.error('Error fetching pole Locations:', error);
//    return [];
//	}
//}
//
//const vegetationMarkerIcon = (color, isSelected) => {
//  const scale = 5;
//  const opacity =  1;
//  const glowColor = isSelected ? 'gold' : '';
//
//  const svg = `
//    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="${scale * 4}" height="${scale * 4}">
//      <defs>
//        <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
//          <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
//          <feMerge>
//            <feMergeNode in="coloredBlur"/>
//            <feMergeNode in="SourceGraphic"/>
//          </feMerge>
//        </filter>
//      </defs>
//      <circle cx="12" cy="12" r="${scale}" fill="${color}" fill-opacity="${opacity}" ${isSelected ? `stroke="${glowColor}" stroke-width="1.5" filter="url(#glow)"` : ''} />
//    </svg>
//  `;
//
//  return {
//    url: 'data:image/svg+xml;charset=UTF-8,' + encodeURIComponent(svg),
//    scaledSize: new window.google.maps.Size(scale * 4, scale * 4),
//    anchor: new window.google.maps.Point(scale * 2, scale * 2)
//  };
//};
//
//const MarkerIcon = (markerType, isSelected) => {
//  if (markerType === 'aerial') {
//    const scale = 4;
//    const borderColor = "black";
//    const fillColor = "red";
//    const dotColor = isSelected ? "gold" : "black";
//    const glowColor = isSelected ? 'gold' : '';
//
//    const svg = `
//      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="${scale * 1}" height="${scale * 1}">
//        <circle cx="12" cy="12" r="${scale * 2}" fill="${fillColor}" stroke="${borderColor}" stroke-width="${scale / 2}" stroke-linecap="round" />
//        <circle cx="12" cy="12" r="${scale / 2}" fill="${dotColor}" />
//        ${isSelected ? `<circle cx="12" cy="12" r="${scale * 2}" fill="none" stroke="${glowColor}" stroke-width="2.0" filter="url(#glow)" />` : ''}
//        <defs>
//          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
//            <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
//            <feMerge>
//              <feMergeNode in="coloredBlur"/>
//              <feMergeNode in="SourceGraphic"/>
//            </feMerge>
//          </filter>
//        </defs>
//      </svg>
//    `;
//
//    return {
//      url: 'data:image/svg+xml;charset=UTF-8,' + encodeURIComponent(svg),
//      scaledSize: new window.google.maps.Size(scale * 4, scale * 4),
//      anchor: new window.google.maps.Point(scale * 2, scale * 2)
//    };
//  }
//};
//
//// TODO NEED TO ADD REFERENCE END POINT
////const MarkerIcon = (markerType, isSelected) => {
////  if (markerType === 'aerial') {
////    const scale = 6;
////    const color = "red"
////    const opacity = isSelected ? 1 : 1;
////    const glowColor = isSelected ? 'gold' : '';
////
////    const svg = `
////      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="${scale * 4}" height="${scale * 4}">
////        <defs>
////          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
////            <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
////            <feMerge>
////              <feMergeNode in="coloredBlur"/>
////              <feMergeNode in="SourceGraphic"/>
////            </feMerge>
////          </filter>
////        </defs>
////        <circle cx="12" cy="12" r="${scale}" fill="${color}" fill-opacity="${opacity}" ${isSelected ? `stroke="${glowColor}" stroke-width="1.5" filter="url(#glow)"` : ''} />
////      </svg>
////    `;
////
////    return {
////      url: 'data:image/svg+xml;charset=UTF-8,' + encodeURIComponent(svg),
////      scaledSize: new window.google.maps.Size(scale * 4, scale * 4),
////      anchor: new window.google.maps.Point(scale * 2, scale * 2)
////    };
////  } else if (markerType === 'reference') {
////    const glowColor = "#f700ff";
////    const scale = 2;
////    const color = "#f700ff";
////    const selectedColor = "#f700ff";
////
////    const svg = `
////      <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="${scale * 4}" height="${scale * 4}">
////        <defs>
////          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
////            <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
////            <feMerge>
////              <feMergeNode in="coloredBlur"/>
////              <feMergeNode in="SourceGraphic"/>
////            </feMerge>
////          </filter>
////        </defs>
////        <polygon
////          points="12,2 15,9 22,9 17,14 18,21 12,17 6,21 7,14 2,9 9,9"
////          fill="${isSelected ? selectedColor : color}"
////          ${isSelected ? `stroke="${glowColor}" stroke-width="2" filter="url(#glow)"` : ''}
////        />
////      </svg>
////    `;
////
////    return {
////      url: 'data:image/svg+xml;charset=UTF-8,' + encodeURIComponent(svg),
////      scaledSize: new window.google.maps.Size(scale * 4, scale * 4),
////      anchor: new window.google.maps.Point(scale * 2, scale * 2)
////    };
////  }
////};
//
//function checkIfPathExists(newPath) {
//  let newFirst = newPath[0]
//  let newSecond = newPath[1];
//  return paths.some(midspan => {
//    let firstPole = midspan.path.map[0];
//    let secondPole = midspan.path.map[1];
//
//    return ((newFirst.lat === firstPole.lat && 
//         newFirst.lng === firstPole.lng &&
//         newSecond.lat === secondPole.lat &&
//         newSecond.lng === secondPole.lng) ||
//        (newFirst.lat === secondPole.lat && 
//         newFirst.lng === secondPole.lng &&
//         newSecond.lat === firstPole.lat &&
//         newSecond.lng === firstPole.lng))
//  }) 
//}
//
//function createNewPath(firstPole, secondPole, map) {
//  const path = {
//    map: [firstPole.position, secondPole.position],
//    geo: [firstPole.geoPosition, secondPole.geoPosition],
//  }
//
//  if (checkIfPathExists(path.map)) {
//    console.log('path exists')
//    return;
//  } else {
//    console.log('path does not exists')
//  }
//
//  const midspan = {
//    path: path,
//    strokeColor: 'limegreen',
//    strokeWeight: 7,
//    type: 'aerial',
//  }
//
//  paths.push(midspan);
//
//  let color = 'limegreen';
//  const polyline = new google.maps.Polyline({
//    path: path.map,
//    map: map,
//    strokeColor: color,
//    strokeWeight: 7
//  });
//
//  createOverlayForPolyline(path.map, polyline, map);
//  polylines.push(polyline);
//}
//
//function createPolyline(path, map) {
//  console.log(path)
//  const polyline = new google.maps.Polyline({
//    path: path.path.map,
//    map: map,
//    strokeColor: path.strokeColor,
//    strokeWeight: path.strokeWeight,
//    type: path.type
//  });
//  createOverlayForPolyline(path.path.map, polyline, map);
//  polylines.push(polyline);
//}
//
//function getLatLng(point) {
//  if (typeof point.lat === 'function' && typeof point.lng === 'function') {
//    return { lat: point.lat(), lng: point.lng() };
//  } else {
//    return { lat: point.lat, lng: point.lng };
//  }
//}
//
//function createOverlayForPolyline(path, polyline, map) {
//  path.slice(0, -1).forEach((point, index) => {
//    const startLatLng = getLatLng(point);
//    const endLatLng = getLatLng(path[index + 1]);
//
//    const start = new google.maps.LatLng(startLatLng.lat, startLatLng.lng);
//    const end = new google.maps.LatLng(endLatLng.lat, endLatLng.lng);
//
//    const distanceMeters = google.maps.geometry.spherical.computeDistanceBetween(start, end);
//    const distanceFeet = distanceMeters * 3.28084;
//    const middlePoint = {
//      lat: (startLatLng.lat + endLatLng.lat) / 2,
//      lng: (startLatLng.lng + endLatLng.lng) / 2
//    };
//
//    const overlay = new google.maps.OverlayView();
//    overlay.onAdd = function () {
//      const div = document.createElement('div');
//      div.className = 'distance-overlay';
//      div.innerHTML = `${distanceFeet.toFixed(2)}'`;
//      div.style.width = 'fit-content';
//      div.style.backgroundColor = 'rgba(255, 255, 255, 0.4)';
//      div.style.padding = '2px 5px';
//      div.style.borderRadius = '3px';
//      div.style.position = 'absolute';
//      div.style.margin = '5px';
//      this.getPanes().floatPane.appendChild(div);
//      this.div = div;
//    };
//
//    overlay.draw = function () {
//      const projection = this.getProjection();
//      const position = projection.fromLatLngToDivPixel(new google.maps.LatLng(middlePoint.lat, middlePoint.lng));
//      const div = this.div;
//      div.style.left = position.x + 'px';
//      div.style.top = position.y + 'px';
//    };
//
//    overlay.onRemove = function () {
//      this.div.parentNode.removeChild(this.div);
//      this.div = null;
//    };
//
//    overlay.setMap(map);
//    polyline.overlay = overlay;
//    distanceOverlays.push(overlay);
//  });
//}
//
////angles for map
//const angleRight = document.querySelector('.fa-angle-right');
//const angleLeft = document.querySelector('.fa-angle-left');
//const angleContainer = document.getElementById('angle-container');
//const renderArea = document.getElementById("potree_render_area");
//const poleInformation = document.getElementById("pole-information")
//let poleInformationBoxOpen = false;
//let arrowIsDisplayed = false;
//let viewerIsOpen = false;
//
//angleRight.addEventListener('click', function() {
//  angleLeft.style.display = 'flex';
//  angleRight.style.display = 'none';
//  if (poleInformationBoxOpen) {
//    //angleContainer.style.left = '635px';
//    angleContainer.style.left = '935px';
//  } else {
//    angleContainer.style.left = '935px';
//  }
//  viewerIsOpen = true
//  openViewer();
//
//});
//
//angleLeft.addEventListener('click', function() {
//  angleRight.style.display = 'flex';
//  angleLeft.style.display = 'none';
//  angleContainer.style.left = '0px';
//  closeViewer();
//  viewerIsOpen = false;
//});
//
//function closeViewer() {
//  renderArea.style.display = 'none';
//}
//
//function openViewer() {
//  renderArea.style.display = 'block';
//}
//
//let currMarker = null;
//function handleMarkerClick(marker, map) {
//  if (routeToolActive) {
//    marker.setIcon(MarkerIcon('aerial', true))
//    if (!currMarker) {
//      currMarker = marker;
//    } else if (currMarker === marker) {
//      return; 
//    } else {
//      createNewPath(marker, currMarker, map);
//      currMarker = marker;
//    }
//
//  } else {
//    if (currMarker) {
//      currMarker.setIcon(MarkerIcon('aerial', false))
//    }
//    marker.setIcon(MarkerIcon('aerial', true))
//    currMarker = marker;
//    const geoPosition = marker.geoPosition;
//    targetTo(viewer, new THREE.Vector3(geoPosition.x, geoPosition.y, geoPosition.z + 3), 0.02);
//    
//    if (arrowIsDisplayed) {
//      return;
//    } else {
//      angleRight.style.display = 'flex';
//      arrowIsDisplayed = true;
//    }
//  }
//}
//
//function handleMarkerDblClick(marker) {
//  if (routeToolActive) return;
//  poleInformationBoxOpen = true; 
//  poleInformation.style.display = 'block'
//
//  renderArea.style.display = 'block';
//  angleContainer.style.left = '935px';
//
//  angleLeft.style.display = 'flex';
//  angleRight.style.display = 'none';
//}
//
//document.addEventListener('keyup', function(event) {
//  if (event.key === 'Escape' || event.keyCode === 27) {
//    selectedMarker = null;
//    markers.forEach(marker => {
//      marker.setIcon(MarkerIcon('aerial', false))
//    })
//    if (poleInformationBoxOpen) {
//      poleInformation.style.display = 'none'
//      poleInformationBoxOpen = false; 
//      angleContainer.style.left = '935px';
//    }
//
//    if (arrowIsDisplayed && !viewerIsOpen) {
//      angleRight.style.display = 'none';
//      arrowIsDisplayed = false;
//    }
//  }
//});
//
//function targetTo(viewer, target) {
//  const {view} = viewer.scene;
//  viewer.scene.orbitControls = true;
//
//  let d = viewer.scene.view.direction.multiplyScalar(-1);
//  let cameraTargetPosition = new THREE.Vector3().addVectors(target, d.multiplyScalar(15));
//  let animationDuration = 200;
//  let easing = TWEEN.Easing.Quartic.Out;
//
//  let tweens = []
//
//    {
//      let value = {x: 0};
//      let tween = new TWEEN.Tween(value).to({x: animationDuration});
//      tween.easing(easing);
//      tweens.push(tween);
//
//      let startPos = viewer.scene.view.position.clone();
//      let targetPos = cameraTargetPosition.clone();
//      let startRadius = viewer.scene.view.radius;
//      let targetRadius = cameraTargetPosition.distanceTo(target)
//
//      tween.onUpdate(() => {
//        let t = value.x / animationDuration;
//        viewer.scene.view.position.x = (1 - t) * startPos.x + t * targetPos.x;
//        viewer.scene.view.position.y = (1 - t) * startPos.y + t * targetPos.y;
//        viewer.scene.view.position.z = (1 - t) * startPos.z + t * targetPos.z + 2;
//
//        viewer.scene.view.radius = (1 - t) * startRadius + t * targetRadius;
//        viewer.setMoveSpeed(viewer.scene.view.radius);
//      });
//
//      tween.onComplete(() => {
//        tweens = tweens.filter(e => e !== tween);
//      });
//
//      tween.start();
//    }
//  view.position.copy(cameraTargetPosition);
//};
//
//
//// DBSCAN
//const dbscanTool = document.querySelector('.dbscan-tool');
//const dbscanModal = document.getElementById('dbscan-modal');
//const closeBtn = document.querySelector('.close-dbscan');
//
//function openDBScanModal() {
//  dbscanModal.style.display = 'block';
//}
//
//function closeDBScanModal() {
//  console.log('here')
//  dbscanModal.style.display = 'none';
//}
//
//dbscanTool.addEventListener('click', openDBScanModal);
//closeBtn.addEventListener('click', closeDBScanModal);
//
//window.addEventListener('click', function(event) {
//  if (event.target === dbscanModal) {
//    closeDBScanModal();
//  }
//});
//
//const dbscanForm = document.getElementById('dbscan-form');
//dbscanForm.addEventListener('submit', async function(event) {
//  event.preventDefault();
//  const epsilon = document.getElementById('eps');
//  const minPts = document.getElementById('min-points');
//  const useMinHeight = document.getElementById('use-min-height');
//  const minHeight = document.getElementById('min-height');
//  console.log(useMinHeight);
//
//  const parsedEps = parseFloat(epsilon).value;
//  const parsedMinPts = parseInt(minPts).value;
//
//  epsilon.value = '';
//  minPts.value = ''; 
//
//  closeDBScanModal();
//  showLoadingModal();
//  let res = await runDbscanForVegetation(parsedEps, parsedMinPts, minHeight);
//  closeLoadingModal();
//});
//
//async function runDbscanForVegetation(parsedEps, parsedMinPts, minHeight) {
//  const options = {
//    parsedEps: parsedEps,
//    parsedMinPts: parsedMinPts,
//    minHeight: minHeight
//  }
//  try {
//    await fetch(`/vegetationDbscan/${id}`, {
//      method: 'POST',
//      headers: {
//        'content-type': 'application/json'
//      },
//      body: JSON.stringify( options )
//    })
//    .then(response => {
//      if (!response.ok) {
//        throw new Error('Network response was no ok');
//      }
//      return response.json();
//    })
//  } catch(error) {
//    console.error('Error running dbscan: ', error);
//  }
//}
//
//
//// Loading modal for dbscan
//function showLoadingModal() {
//  const loadingModal = document.getElementById('loading-modal');
//  loadingModal.style.display = 'block';
//}
//
//// Function to close loading modal
//function closeLoadingModal() {
//  const loadingModal = document.getElementById('loading-modal');
//  loadingModal.style.display = 'none';
//}
//
//// END OF DBSCAN
//
//
//// VEGETATION ENCROACHMENTS
//let vegetationToolActive = false;
//let vegetationEncroachments = [];
//let fetchedFromServer = false;
//
//const vegetationTool = document.querySelector('.vegetation-tool');
//vegetationTool.addEventListener('click', toggleVegetationTool);
//
//async function toggleVegetationTool() {
//  if (paths.length === 0) {
//    alert('Midspans must first be save to generate vegetation encroachments!')
//    return
//  }
//  vegetationToolActive = true;
//
//  if (vegetationToolActive) {
//    if (!fetchedFromServer) {
//      await fetchVegetationEncroachments()
//    }
//    displayVegetationEncroachments();
//    populateVegatationSidebar();
//  } else {
//    removeVegetationEncroachments();
//    vegetationSidebar.style.display = 'none';  
//  }
//}
//
//const vegetationSidebar = document.querySelector('#vegetation-container');
//
//function populateVegatationSidebar() {
//  if (vegetationEncroachments.length === 0) return;
//  vegetationSidebar.style.display = 'block';  
//  
//  vegetationSidebar.innerHTML = '';
//
//  let encroachmentsArray = Object.values(vegetationEncroachments);
//
//  // Sort the array by distance
//  encroachmentsArray.sort((a, b) => a.dist - b.dist);
//
//  encroachmentsArray.forEach((vegetation) => {
//
//    let distance = vegetation[0].dist
//    let color;
//    if (distance >= 10) {
//      color = 'limegreen'
//    } else if (distance >= 5) {
//      color = 'yellow'
//    } else {
//      color = 'red'
//    }
//
//
//    let locationLatLng = localToGeographic(vegetation[0].position[0], vegetation[0].position[1]);
//    const listContainer = document.createElement('div')
//    listContainer.classList.add('list-container');
//
//    listContainer.dataset.x = vegetation[0].position[0];
//    listContainer.dataset.y = vegetation[0].position[1];
//    listContainer.dataset.z = vegetation[0].position[2];
//
//    const circleDot = document.createElement('div');
//    circleDot.classList.add('circle-dot');
//    circleDot.style.backgroundColor = color;
//    listContainer.appendChild(circleDot);
//
//    const listItem = document.createElement('div');
//    listItem.classList.add('vegetation-item');
//    listItem.innerHTML += `
//       <p><strong>lat/lng:</strong> (${locationLatLng.lat}, ${locationLatLng.lng})</p>
//       <details>
//         <summary>Additional Details</summary>
//         <p><strong>Distance:</strong> ${distance.toFixed(2)} feet</p>
//         <p><strong>Position:</strong> (${vegetation[0].position[0]}, ${vegetation[0].position[1]}, ${vegetation[0].position[2]})</p>
//       </details>
//    `;
//
//    listContainer.appendChild(listItem)
//    // Append the list item to the sidebar
//    vegetationSidebar.appendChild(listContainer);
//  })
//}
//
//vegetationSidebar.addEventListener('click', function(event) {
//  const listContainer = event.target.closest('.list-container');
//  if (listContainer) {
//    const x = Number(listContainer.dataset.x);
//    const y = Number(listContainer.dataset.y);
//    const z = Number(listContainer.dataset.z);
//    targetTo(viewer, new THREE.Vector3(x, y, z + 3), 0.02);
//    renderArea.style.display = 'block';
//    //angleContainer.style.left = '635px';
//    //angleLeft.style.display = 'flex';
//    //angleRight.style.display = 'none';
//  }
//});
//
//let vegetationMarkers = []
//
//function displayVegetationEncroachments() {
//  if (vegetationEncroachments.length === 0) {
//    alert('no vegetation encroachments!')
//    //popup displaying no vegetation encroachments
//  } else {
//    console.log(vegetationEncroachments)
//    for (let point in vegetationEncroachments) {
//      let vegetations = vegetationEncroachments[point]
//      let chosen = null;
//      vegetations.forEach(veg => {
//        if (chosen === null) {
//          chosen = veg;
//        } else if(veg.dist < chosen.dist) {
//          chosen = veg;
//        }
//      })
//
//      let distance = chosen.dist
//      let color;
//      if (distance >= 10) {
//        color = 'limegreen'
//      } else if (distance >= 5) {
//        color = 'yellow'
//      } else {
//        color = 'red'
//      }
//
//
//      let locationLatLng = localToGeographic(chosen.position[0], chosen.position[1]);
//      const position = new google.maps.LatLng(locationLatLng.lat, locationLatLng.lng);
//      
//      const markerOptions = {
//        geoPosition: {
//          "x": chosen.position[0],
//          "y": chosen.position[1],
//          "z": chosen.position[2],
//          "height": chosen.position[3],
//        },
//        position: position,
//        map: map,
//        selected: false,
//        icon: vegetationMarkerIcon(color, false),
//        draggable: true,
//      };
//
//      const marker = new google.maps.Marker(markerOptions);
//      //marker.addListener('click', (e) => handleMarkerClick(marker, map));
//      //marker.addListener('dblclick', (e) => handleMarkerDblClick(marker, map));
//      vegetationMarkers.push(marker);
//    }
//  }
//}
//
//function removeVegetationEncroachments() {
//  if (vegetationEncroachments.length === 0) {
//    return;
//  } else {
//    vegetationMarkers.forEach(marker => {
//      marker.setMap(null)
//    })
//  }
//}
//async function fetchVegetationEncroachments() {
//  try {
//    const response = await fetch(`/vegetationEncroachments/${id}`)
//    if (!response.ok) {
//      throw new Error('Failed to fetch vegetation encroachments');
//    }
//
//    //server should return empty array in none
//    vegetationEncroachments = await response.json()
//    fetchedFromServer = true;
//  } catch (error) {
//    console.error('Error fetching vegetation encroachments from the server', error.message);
//  } finally {
//    // close bar
//  }
//}
//
//
//// route tool
//// TODO FIX THE BUGS ASSOCIATED WITH ADDING AND REMOVE PATHS
//let routeToolActive = false;
//const routeTool = document.querySelector('.route-tool');
//routeTool.addEventListener('click', addRoutes);
//
//const saveContainer = document.querySelector('#save-path-container');
//const exitPathSelection = document.querySelector('.exit-path-selection');
//const savePathSelection = document.querySelector('.save-path-selection');
//// this is so we do not remove the existing polylines
//let tempPolylines = []
//let tempDistanceOverlays = []
//exitPathSelection.addEventListener('click', function() {
//  tempPolylines.forEach(polyline => {
//    polyline.setMap(null);
//  })
//
//  markers.forEach(marker => {
//    marker.setIcon(MarkerIcon('aerial', false));
//  })
//
//  tempDistanceOverlays.forEach(overlay => {
//    overlay.setMap(null);
//  })
//
//  paths = [];
//  tempPolylines = [];
//  tempDistanceOverlays = [];
//  currMarker = null;
//
//  saveContainer.style.display = 'none';
//  routeTool.style.border = 'none'
//  routeTool.style.borderBottom = '1px solid black'
//  routeToolActive = false;
//})
//
//savePathSelection.addEventListener('click', function() {
//  //save to database
//  toggleRouteSideBar();
//  routeTool.style.border = 'none'
//  routeTool.style.borderBottom = '1px solid black'
//  polylines.push(tempPolylines)
//  fetch(`/savePaths/${id}`, {
//    method: 'POST',
//    headers: {
//      'content-type': 'application/json'
//    },
//    body: JSON.stringify( paths )
//  })
//  .then(response => {
//    if (!response.ok) {
//      throw new Error('Network response was no ok');
//    }
//    return response.json();
//  })
//  .then(data => {
//    console.log(data);
//  })
//  .catch(error => {
//    console.error('Error saving data: ', error);
//  })
//})
//
//function toggleRouteSideBar() {
//  if (routeToolActive) {
//    saveContainer.style.display = 'none';
//  } else {
//    saveContainer.style.display = 'flex';
//  }
//}
//
//function addRoutes() {
//  if (routeToolActive) return;
//  toggleRouteSideBar();  
//  routeToolActive = true;
//  
//  if (routeToolActive) {
//    routeTool.style.border = '1px solid blue'
//
//  } else {
//    routeTool.style.border = 'none'
//    routeTool.style.borderBottom = '1px solid black'
//  }
//}
