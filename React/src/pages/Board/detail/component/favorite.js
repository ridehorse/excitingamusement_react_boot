import { useState, useEffect } from 'react';
import axios from 'axios';
import styles from '../detail.module.css'

function Favorite(props) {
    const { viewData } = props;
    const [favoriteData, setFavoriteData] = useState(null);


    useEffect(() => {
        const fetchData = async () => {
            await fetchFavoriteData();
        };
        fetchData();
    }, []);

    const fetchFavoriteData = async () => {

        await axios.get('http://localhost:8080/board/favoriteBoard', {
            params: {
                board_id: viewData.board_id
            }
        }).then(response => {
            setFavoriteData(response.data[0]);
        }).catch(error => {
        });
    };

    if (favoriteData === null) {
        return <div>Loading...</div>;
    }


    const loginCheck = (member_id) => {
        if (member_id !== null) { window.alert("로그인해주세요!"); return 0; };
        return 1;
    }

    const handleFavoriteEvent = (rs) => {

        const member_id = sessionStorage.getItem("MEMBER_ID");
        let loginChec = loginCheck(member_id);

        if (loginChec === 1) {
            axios
                .post('http://localhost:8080/board/favoriteBoard', {

                    board_id: viewData.board_id,
                    checkData: rs,
                    member_id: member_id,
                    //favorite: viewData.favorite,
                    // hate: viewData.hate

                })
                .then(response => {
                    fetchFavoriteData();
                })
                .catch(error => {
                });
        }

        // }
    };

    return (
        <div className={styles.favorite}>
            <span>{favoriteData.favorite}</span>
            <span style={{ margin: '0 10px' }}></span>
            <span onClick={() => handleFavoriteEvent(1)}>
                <img src="https://cdn-icons-png.flaticon.com/512/4411/4411029.png" alt="1" style={{ width: '75px' }} />
            </span>
            <span onClick={() => handleFavoriteEvent(2)}>
                <img src="https://cdn-icons-png.flaticon.com/512/4510/4510629.png" alt="1" style={{ width: '75px' }} />
            </span>
            <span style={{ margin: '0 10px' }}></span>
            <span>{favoriteData.hate}</span>
        </div>
    );
}

export default Favorite;