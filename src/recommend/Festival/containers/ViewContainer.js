import React, { useEffect, useState, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import styled from 'styled-components';
import { apiGet } from '../apis/apiInfo';
import Loading from '../../../commons/components/Loading';
import KakaoMap from '../../../map/KakaoMap';
import ItemImage from '../components/ItemImage';
import ItemDescription from '../components/ItemDescription';

const Wrapper = styled.div`
  display: flex;
  margin-bottom: 15px;
`;

const ViewContainer = ({ setSubPageTitle }) => {
  const [item, setItem] = useState(null);
  const [loading, setLoading] = useState(false);
  const [mapOptions, setMapOptions] = useState({ height: '400px', zoom: 3 });

  const { seq } = useParams();

  useEffect(() => {
    setLoading(true);

    apiGet(seq).then((item) => {
      setSubPageTitle(item.title);
      setItem(item);

      const position = { lat: item.latitude, lng: item.longitude };
      setMapOptions((opt) => {
        const options = item.latitude
          ? { ...opt, center: position, marker: position }
          : { ...opt, address: item.address };
        return options;
      });
    });

    setLoading(false);
  }, [seq, setSubPageTitle]);

  const onShowImage = useCallback((imageUrl1) => {
    console.log("이미지 주소", imageUrl1);
  }, []);

  if (loading || !item) {
    return <Loading />;
  }

  return (
    <>
      <Wrapper>
        {item.photoUrl1 && <ItemImage images={item.photoUrl1} onClick={onShowImage} />}
        <ItemDescription item={item} />
      </Wrapper>
      <KakaoMap {...mapOptions} />
    </>
  );
};

export default React.memo(ViewContainer);
