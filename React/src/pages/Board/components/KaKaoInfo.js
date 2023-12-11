import { useEffect } from 'react';

const KaKaoInfo = {
    init: () => {
        const script = document.createElement('script');
        script.src = 'https://developers.kakao.com/sdk/js/kakao.js';
        script.onload = () => {
            window.Kakao.init("6b91f3bcf4e7a2744f0dd70c0c85c6ab");
        };
        document.body.appendChild(script);
        return () => {
            document.body.removeChild(script);
        };
    },

    sendLinkCustom: () => {
        if (window.Kakao) {
            window.Kakao.Link.sendCustom({
                templateId: 53911,
            });
        }
    },

    sendLinkDefault: () => {
        if (window.Kakao) {
            window.Kakao.Link.sendDefault({
                objectType: 'feed',
                content: {
                    title: 'amusement',
                    description: '#놀이공원 #할인 #Link Description',
                    imageUrl: 'https://cdn.aitimes.com/news/photo/202205/144590_150861_334.jpg',
                    link: {
                        mobileWebUrl: 'https://developers.kakao.com',
                        webUrl: document.location.href,
                    },
                },
                social: {
                    likeCount: 100,
                    commentCount: 200,
                    sharedCount: 300,
                },
                buttons: [
                    {
                        title: '보러가기',
                        link: {
                            mobileWebUrl: 'https://developers.kakao.com',
                            webUrl: document.location.href,
                        },
                    },
                ],
            });
        }
    },
};

KaKaoInfo.init(); // KakaoApi를 초기화 합니다.

export default KaKaoInfo;