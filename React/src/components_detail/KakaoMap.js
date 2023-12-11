import React, { useEffect } from "react";
import { Container } from "react-bootstrap";

const { kakao } = window;

const KakaoMap = (props) => {
  const lat = props.lat;
  const lng = props.lng;

  //[]에 lat, lng 추가!!!!
  useEffect(() => {
    const container = document.getElementById("map");
    const options = {
      center: new kakao.maps.LatLng(lat, lng),
      markerPosition: new kakao.maps.LatLng(lat, lng),
      level: 6,
    };
    const map = new kakao.maps.Map(container, options);

    // 마커 생성!!
    let marker = new kakao.maps.Marker({
      position: options.markerPosition,
    });

    //   // 마커를 지도 위에 표시
    marker.setMap(map);
  }, [lat, lng]);

  return (
    <Container id="location" className="py-5">
      <header className="header-title">위치</header>
      <div className="kakao-map">
        <div
          id="map"
          style={{
            width: "100%",
            height: "400px",
            margin: "auto",
            borderRadius: "20px",
          }}
        />
      </div>
    </Container>
  );
};

export default KakaoMap;
