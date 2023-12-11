import React, { useEffect, useState } from 'react';
import styles from './announcementDetail.module.css'
import axios from 'axios';
import { useLocation } from 'react-router-dom';





function AnnouncementDetail() {

    const [viewData, setViewData] = useState([]);
    const [imgData, setImgData] = useState([]);
    const [deleteCheck, setDeleteCheck] = useState(0)
    const location = useLocation()




    useEffect(() => {
        async function fetchData() {
            const urlParams = new URLSearchParams(location.search);
            const announcement_num = urlParams.get("announcement_num");
            await data(announcement_num);
        }
        fetchData();
    }, []);


    const data = async (announcement_num) => {



        await axios.get('http://localhost:8080/customer/view', {
            params: {
                announcement_num: announcement_num
            }
        }).then((response) => {
            console.log(response.data)
            console.log(response.data.boardImg)
            setImgData(response.data.boardImg)
            setViewData(response.data);
        }).catch((error) => {
            console.log(error);
            if (deleteCheck === 0) {
                window.alert("해당 페이지는 존재 하지 않습니다.")
                window.location.href = "/announcement"
            }
        });


    };

    // 게시물 삭제
    const deleteBoard = () => {

        if (window.confirm("정말로 삭제하시겠습니까?")) {
            axios.delete("http://localhost:8080/customer/deleteBoardImg", {
                params: { announcement_num: viewData.announcement_num }
            }).then(() => {
                window.alert("삭제완료")
                window.location.href = "/inquiry";
            }).then(() => {
                axios.delete("http://localhost:8080/customer/deleteAnnouncement", {
                    params: {
                        announcement_num: viewData.announcement_num,
                    },
                })
                    .then(() => {
                        window.location.href = "/announcement";
                        setDeleteCheck(1);
                    })
                    .catch((error) => {
                        console.log(error);
                    });
            })

        }
    };


    //게시물 업데이트
    const updateBoard = () => {

        window.location.href = `/uploadAnnouncement?announcement_num=${viewData.announcement_num}`
    }

    const rollbackpage = () => {
        window.location.href = "/announcement"
    }




    //리턴
    return (
        <div>
            <section className='notice'>
                <div className={styles.wrap}>
                    {/* <Advertisment_leftSide /> */}
                    <div className={styles.view_wrap}>

                        {/*위의 기본적인 글 정보들*/}
                        <div className={styles.header}>
                            <div className={styles.header_inner} style={{ textAlign: 'left' }}>
                                <p style={{ marginBottom: '10', fontSize: '20' }}><b>{viewData.c_title}</b></p>

                            </div >
                        </div >
                        <hr></hr>
                        <br></br>


                        { /* 이미지*/}
                        <div className={styles.main_content}>
                            {imgData && imgData.map((imgData, index) => (
                                <div key={index} className={styles.image_wrap} style={{ marginLeft: 200 }}  >
                                    <img src={imgData.boardimg} alt="Board Image22" style={{ margin: '20', maxWidth: '1000' }} />
                                </div>
                            ))}
                            <br />
                            <div style={{ clear: 'both' }}></div>
                            {/*글 내용*/}
                            <div className={styles.content} dangerouslySetInnerHTML={{ __html: viewData.c_content }}></div>

                            <div className={styles.view_btn}>
                                <input type="button" className={[styles.btn, styles.btn_blue].join(" ")} id="board_delete" value='삭제' onClick={deleteBoard} />
                                <input type="button" className={[styles.btn, styles.btn_blue].join(" ")} id="board_update" value='수정'
                                    onClick={updateBoard} />

                            </div>
                        </div>
                        <hr style={{ border: 0 }}></hr>

                    </div >
                </div >
                <div className={styles.list_wrap} style={{ marginLeft: 400 }}>
                    <input type="button" className={styles.listback} id="listback" onClick={rollbackpage} value='목록' />
                </div>

                <hr />
            </section >
        </div >
    );
}

export default AnnouncementDetail;