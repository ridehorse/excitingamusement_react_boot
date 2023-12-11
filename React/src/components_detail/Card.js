import { useNavigate } from "react-router-dom";

import "./card.scss";

export const Card = ({path, name, country, img, id, location, avg, review_cnt}) => {
  const navigate = useNavigate();
  
  return (
    avg !== undefined
    ? <div className="card-wrapper" onClick={e => {
      e.preventDefault();
      // navigate(`/${path}/${id}`);
      window.location.replace(`/${path}/${id}`);
    }}>
      <div className="card-body-img">
        <img src={img} alt="img"/>
      </div>
      <div className="card-body-text">
        <div className="card-body-text-title">{name}</div>
      </div>
      <div className="card-footer">
        <div className="card-body-text-content">
          <br/>
          <p>{country}</p>
        </div>
        <div className="card-body-text-content">
          {(() => {
              const array = [];
              for(let i = 0; i < Math.floor(avg); i++) {
                  array.push(<span style={{fontSize:'1.1rem'}} key={i}>⭐</span>);
              }
              return array;
          })()}
          <br/><br/><p style={{fontWeight:'bold'}}>&nbsp;({avg}점)</p>
        </div>
        <div className="card-body-text-content"><br/>
          <p style={{fontWeight:'bold'}}>review: {review_cnt}개</p>
        </div>
      </div>
    </div>
    : 
    <div className="card-wrapper" onClick={e => {
      e.preventDefault();
      navigate(`/${path}/${id}`);
    }}>
      <div className="card-body-img">
        <img src={img} alt="img"/>
      </div>
      <div className="card-body-text">
        <div className="card-body-text-title">{name}</div>
      </div>
      <div className="card-footer">
        <div className="card-body-text-content">
          {country}
        </div>
      </div>
    </div>
  );
};