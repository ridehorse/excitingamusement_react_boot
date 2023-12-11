import axios from "axios";
import { useState } from "react";
import { emojiList } from './emojis';
import styles from '../detail.module.css'



function WriteComment(props) {

    const [comment, setComment] = useState('');
    const { board_id } = props;
    //글자수 제한
    const limitComment = (event) => {
        const value = event.target.value;
        if (value.length <= 200) {
            setComment(value);
        }
    }


    const emo = (event, emoji) => {
        event.preventDefault();
        const textarea = document.getElementById("comment");
        const startPos = textarea.selectionStart;
        const endPos = textarea.selectionEnd;
        const value = textarea.value;
        const newValue =
            value.substring(0, startPos) +
            emoji +
            value.substring(endPos, value.length);
        setComment(newValue);
        textarea.focus();
        textarea.setSelectionRange(startPos + emoji.length, startPos + emoji.length);
    }

    const loginCheck = (member_id) => {
        if (member_id === null) { window.alert("로그인해주세요!"); return; };

    }


    function commentInsert() {
        const member_id = sessionStorage.getItem("MEMBER_ID");
        const comment = document.getElementById("comment");

        loginCheck(member_id);

        if (member_id === null) {
            alert("로그인해주세요!");
            window.location.href = "/login";
        } else if (comment.value === '') {
            alert("빈 내용은 작성하실 수 없습니다");
        } else {


            axios
                .post('/board/reply-insert', {
                    b_reply: comment.value,
                    board_id: board_id,
                    member_id: member_id,
                })
                .then(() => {
                    setComment('');
                    window.alert('댓글이 성공적으로 추가되었습니다.');
                    props.onAddComment({
                        b_reply: comment.value,
                        board_id: board_id,
                        member_id: member_id,
                        // 필요한 다른 정보를 추가하세요
                    });
                })
                .catch((error) => {
                });


        }

    }

    return (

        <div>
            <textarea
                name="comment"
                id="comment"
                className={styles.comment}
                cols=""
                rows="4"
                placeholder="여러분의 소중한 댓글을 입력해주세요."
                value={comment}
                onChange={limitComment}>
            </textarea>
            <div className={styles.emoticons} id={styles.emoticons}>
                이모티콘:
                {emojiList.map((emojiData, index) =>
                    <img
                        key={index}
                        onClick={(event) => emo(event, emojiData.emoji)}
                        src={emojiData.src}
                        alt={emojiData.alt}
                        title={emojiData.title}
                    />
                )}

                <div className={styles.comment_cnt} id={styles.comment_cnt}>({comment.length} / 200)
                    <input
                        type="button"
                        className={[styles.btn, styles.btn_blue].join(' ')}
                        name="comment-insert"
                        id="comment-insert"
                        onClick={commentInsert}
                        value="작성" />
                </div>
            </div>
        </div>
    )
}

export default WriteComment
