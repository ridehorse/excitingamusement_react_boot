import './kakaoAPI.css'
import KaKaoInfo from './KaKaoInfo'

function KakaoAPI() {





    const openWindow = () => {

        let open = document.querySelector('.pop_wrap')
        open.style.display = 'block';

    }
    const closeWindow = () => {

        let open = document.querySelector('.pop_wrap')
        open.style.display = 'none';

    }

    return (
        <>
            <div className="content E-Solution" id="content">
                <a
                    href="#pop_info_1"
                    className="btn_open"
                    id="btn_open"
                    onClick={openWindow}>
                    <img
                        src="https://cdn-icons-png.flaticon.com/512/1244/1244758.png?w=360"
                        alt="kakaoimg1"
                        width="50"
                        height="50" />
                </a>
                <div id="pop_info_1" className="pop_wrap" style={{ display: 'none' }}>
                    <div className="pop_inner">
                        <img
                            src="https://play-lh.googleusercontent.com/Ob9Ys8yKMeyKzZvl3cB9JNSTui1lJwjSKD60IVYnlvU2DsahysGENJE-txiRIW9_72Vd"
                            alt="kakaoimg2"
                            style={{ width: '70px', cursor: 'pointer' }}
                            onClick={KaKaoInfo.sendLinkDefault} // sendLinkDefault 기능을 실행합니다.
                        />
                        <br />
                        <button type="button" className="btn_close" onClick={closeWindow}>닫기</button>
                    </div>
                </div>
            </div>
        </>
    );


}


export default KakaoAPI;