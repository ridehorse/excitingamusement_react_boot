import React, { useRef, useEffect } from 'react';
import L from "leaflet";

const MyMapComponent = ({ markers }) => {
  const mapRef = useRef(null);
  const markerLayerRef = useRef(null);

  // 지도 생성
  useEffect(() => {
    if (mapRef.current) {
      const map = L.map(mapRef.current, { scrollWheelZoom: false });

      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution:
          'Map data &copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a> contributors',
        maxZoom: 18,
      }).addTo(map);

      L.Icon.Default.imagePath = '//cdnjs.cloudflare.com/ajax/libs/leaflet/1.3.1/images/';

      // featureGroup (markerLayer) 생성 및 지도에 추가
      const markerLayer = new L.featureGroup().addTo(map);
      markerLayerRef.current = { map, markerLayer };

      return () => {
        map.remove();
      };
    }
  }, []);

  // 마커 추가/업데이트
  useEffect(() => {
    if (markerLayerRef.current) {
      const { map, markerLayer } = markerLayerRef.current;
      markerLayer.clearLayers(); // 이전 마커 삭제

      let markerElements = [];
      for (let i = 0; i < markers.length; i++) {
        const marker = L.marker([markers[i]['a_lat'], markers[i]['a_lng']]).addTo(markerLayer);
        marker.bindPopup(markers[i]['a_name']);
        markerElements.push(marker);
      }

      if (!(markerElements.length === 0)) {
        // 마커 포함하는 영역까지 줌확대 및 위치설정
        const group = new L.featureGroup(markerElements);
        map.fitBounds(group.getBounds(), {
          maxZoom: 15,
        });
      }
    }
  }, [markers]);

  return (
    <div id="map" ref={mapRef} style={{ height: '300px', width: '100%' }} />
  );
};

MyMapComponent.defaultProps = {
  markers: []
};

export default MyMapComponent;
