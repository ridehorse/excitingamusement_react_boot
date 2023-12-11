import React, { useState } from 'react';
import './starRating.scss';
import 'bootstrap/dist/css/bootstrap.min.css';
import { InputGroup, Label } from 'react-bootstrap';

const StarRating = ({starRatingFunc}) => {
    const [selectedRating, setSelectedRating] = useState(null);
    const ratings = [1,2,3,4,5];

    const styles = {
        checkedLabel: {
            textShadow: '0 0 0 gold',
        },
    };

    //자식 컴포넌트에서 부모 컴포넌트로 데이터 전달할 때!
    //=> input에서 onChange 부분에 handleRatingChange의 파라미터에는 그때그때마다 선택한 점수 값이 들어가고
    //그 값이 곧 부모 컴포넌트로 전달하는 데이터이므로 handleRatingChange 함수에서 부모 컴포넌트로 전달하는
    //함수를 정의해야 함!!!!! 
    const handleRatingChange = value => {
        setSelectedRating(value);
        starRatingFunc(value);
    }

    // 이렇게 하면 안됨
    // starRatingFunc(selectedRating);

    return (
        <div style={{display:'flex'}}>
            <div className='star-rating'>
                {ratings.map((rating, index) => (
                    <React.Fragment key={rating}>
                    <input
                        type="radio"
                        name="rating"
                        value={rating}
                        id={`rate${rating}`}
                        checked={selectedRating === rating}
                        onChange={() => {
                            handleRatingChange(rating)}
                        }
                    />
                    <label htmlFor={`rate${rating}`}
                        style={
                            selectedRating !== null && index <= ratings.indexOf(selectedRating) 
                            ? styles.checkedLabel : null}>
                        ⭐
                    </label>
                    </React.Fragment>
                ))}
            </div>
            <div style={{marginLeft:'10%', fontSize:'1.8rem', fontWeight:'bold'}}>
                점수: {selectedRating}</div>
        </div>
    );
};

export default StarRating;